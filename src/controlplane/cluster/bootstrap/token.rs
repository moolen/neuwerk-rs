use std::collections::HashMap;
use std::fs;
use std::path::Path;

use base64::Engine;
use serde::Deserialize;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Debug, Deserialize)]
struct TokenFile {
    tokens: Vec<TokenEntry>,
}

#[derive(Debug, Deserialize)]
struct TokenEntry {
    kid: String,
    token: String,
    #[serde(default)]
    valid_from: Option<String>,
    #[serde(default)]
    valid_until: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedToken {
    pub kid: String,
    pub token: Vec<u8>,
    pub valid_from: Option<OffsetDateTime>,
    pub valid_until: Option<OffsetDateTime>,
}

#[derive(Debug)]
pub struct TokenStore {
    tokens: HashMap<String, ParsedToken>,
}

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("failed to read token file: {0}")]
    Read(#[from] std::io::Error),
    #[error("failed to parse token json: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("token entry missing kid or token")]
    MissingField,
    #[error("duplicate token kid: {0}")]
    DuplicateKid(String),
    #[error("invalid token encoding for kid {0}")]
    InvalidTokenEncoding(String),
    #[error("invalid valid_from for kid {0}")]
    InvalidValidFrom(String),
    #[error("invalid valid_until for kid {0}")]
    InvalidValidUntil(String),
    #[error("invalid validity window for kid {0}")]
    InvalidValidityWindow(String),
    #[cfg(unix)]
    #[error("bootstrap token file permissions too open: {0:o} (expected 0o600 or stricter)")]
    InsecurePermissions(u32),
    #[error("no valid tokens found")]
    NoValidTokens,
}

impl ParsedToken {
    pub fn is_valid_at(&self, now: OffsetDateTime) -> bool {
        if let Some(from) = self.valid_from {
            if now < from {
                return false;
            }
        }
        if let Some(until) = self.valid_until {
            if now > until {
                return false;
            }
        }
        true
    }
}

impl TokenStore {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, TokenError> {
        let path = path.as_ref();
        #[cfg(unix)]
        validate_token_file_permissions(path)?;
        let contents = fs::read_to_string(path)?;
        let file: TokenFile = serde_json::from_str(&contents)?;
        let mut tokens = HashMap::new();

        for entry in file.tokens {
            if entry.kid.is_empty() || entry.token.is_empty() {
                return Err(TokenError::MissingField);
            }

            if tokens.contains_key(&entry.kid) {
                return Err(TokenError::DuplicateKid(entry.kid));
            }

            let token = decode_token(&entry.kid, &entry.token)?;
            let valid_from = parse_opt_timestamp(
                entry.valid_from.as_deref(),
                &entry.kid,
                TokenError::InvalidValidFrom,
            )?;
            let valid_until = parse_opt_timestamp(
                entry.valid_until.as_deref(),
                &entry.kid,
                TokenError::InvalidValidUntil,
            )?;
            if let (Some(from), Some(until)) = (valid_from, valid_until) {
                if from > until {
                    return Err(TokenError::InvalidValidityWindow(entry.kid));
                }
            }

            tokens.insert(
                entry.kid.clone(),
                ParsedToken {
                    kid: entry.kid,
                    token,
                    valid_from,
                    valid_until,
                },
            );
        }

        Ok(Self { tokens })
    }

    pub fn get(&self, kid: &str) -> Option<&ParsedToken> {
        self.tokens.get(kid)
    }

    pub fn current(&self, now: OffsetDateTime) -> Result<&ParsedToken, TokenError> {
        let mut best: Option<&ParsedToken> = None;

        for token in self.tokens.values() {
            if !token.is_valid_at(now) {
                continue;
            }
            best = match best {
                None => Some(token),
                Some(existing) => Some(select_preferred(existing, token)),
            };
        }

        best.ok_or(TokenError::NoValidTokens)
    }
}

fn select_preferred<'a>(a: &'a ParsedToken, b: &'a ParsedToken) -> &'a ParsedToken {
    let a_from = a.valid_from.unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let b_from = b.valid_from.unwrap_or(OffsetDateTime::UNIX_EPOCH);
    if b_from > a_from {
        return b;
    }
    if b_from < a_from {
        return a;
    }

    match (a.valid_until, b.valid_until) {
        (Some(a_until), Some(b_until)) => {
            if b_until > a_until {
                b
            } else {
                a
            }
        }
        (None, Some(_)) => a,
        (Some(_), None) => b,
        (None, None) => {
            if b.kid > a.kid {
                b
            } else {
                a
            }
        }
    }
}

fn parse_opt_timestamp(
    raw: Option<&str>,
    kid: &str,
    mk_err: fn(String) -> TokenError,
) -> Result<Option<OffsetDateTime>, TokenError> {
    raw.map(|value| OffsetDateTime::parse(value, &Rfc3339).map_err(|_| mk_err(kid.to_string())))
        .transpose()
}

fn decode_token(kid: &str, token: &str) -> Result<Vec<u8>, TokenError> {
    if let Some(rest) = token.strip_prefix("hex:") {
        return hex::decode(rest).map_err(|_| TokenError::InvalidTokenEncoding(kid.to_string()));
    }
    if let Some(rest) = token.strip_prefix("b64:") {
        return base64::engine::general_purpose::STANDARD
            .decode(rest)
            .map_err(|_| TokenError::InvalidTokenEncoding(kid.to_string()));
    }
    Err(TokenError::InvalidTokenEncoding(kid.to_string()))
}

#[cfg(unix)]
fn validate_token_file_permissions(path: &Path) -> Result<(), TokenError> {
    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(TokenError::InsecurePermissions(mode));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use tempfile::NamedTempFile;

    #[test]
    fn parses_and_selects_current_token() {
        let mut file = NamedTempFile::new().unwrap();
        let json = r#"{
  "tokens": [
    { "kid": "old", "token": "hex:deadbeef", "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2026-03-01T00:00:00Z" },
    { "kid": "new", "token": "b64:Zm9vYmFy", "valid_from": "2026-02-15T00:00:00Z", "valid_until": "2026-12-01T00:00:00Z" }
  ]
}"#;
        std::io::Write::write_all(&mut file, json.as_bytes()).unwrap();
        let store = TokenStore::load(file.path()).unwrap();
        let now = OffsetDateTime::parse("2026-02-20T00:00:00Z", &Rfc3339).unwrap();
        let current = store.current(now).unwrap();
        assert_eq!(current.kid, "new");
        assert_eq!(current.token, b"foobar");
    }

    #[test]
    fn rejects_duplicate_kid() {
        let mut file = NamedTempFile::new().unwrap();
        let json = r#"{
  "tokens": [
    { "kid": "dup", "token": "hex:deadbeef" },
    { "kid": "dup", "token": "hex:feedface" }
  ]
}"#;
        std::io::Write::write_all(&mut file, json.as_bytes()).unwrap();
        let err = TokenStore::load(file.path()).unwrap_err();
        match err {
            TokenError::DuplicateKid(kid) => assert_eq!(kid, "dup"),
            _ => panic!("unexpected error: {err:?}"),
        }
    }

    #[test]
    fn current_rejects_future_only_tokens() {
        let mut file = NamedTempFile::new().unwrap();
        let json = r#"{
  "tokens": [
    { "kid": "future", "token": "hex:deadbeef", "valid_from": "2027-01-01T00:00:00Z" }
  ]
}"#;
        std::io::Write::write_all(&mut file, json.as_bytes()).unwrap();
        let store = TokenStore::load(file.path()).unwrap();
        let now = OffsetDateTime::parse("2026-02-20T00:00:00Z", &Rfc3339).unwrap();
        let err = store.current(now).unwrap_err();
        assert!(matches!(err, TokenError::NoValidTokens));
    }

    #[test]
    fn rejects_invalid_validity_window() {
        let mut file = NamedTempFile::new().unwrap();
        let json = r#"{
  "tokens": [
    { "kid": "bad", "token": "hex:deadbeef", "valid_from": "2026-03-01T00:00:00Z", "valid_until": "2026-02-01T00:00:00Z" }
  ]
}"#;
        std::io::Write::write_all(&mut file, json.as_bytes()).unwrap();
        let err = TokenStore::load(file.path()).unwrap_err();
        assert!(matches!(err, TokenError::InvalidValidityWindow(k) if k == "bad"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_world_readable_token_file() {
        let mut file = NamedTempFile::new().unwrap();
        let json = r#"{
  "tokens": [
    { "kid": "k", "token": "hex:deadbeef" }
  ]
}"#;
        std::io::Write::write_all(&mut file, json.as_bytes()).unwrap();
        let perms = std::fs::Permissions::from_mode(0o644);
        std::fs::set_permissions(file.path(), perms).unwrap();
        let err = TokenStore::load(file.path()).unwrap_err();
        assert!(matches!(err, TokenError::InsecurePermissions(0o644)));
    }

    #[cfg(unix)]
    #[test]
    fn accepts_strict_token_file_permissions() {
        let mut file = NamedTempFile::new().unwrap();
        let json = r#"{
  "tokens": [
    { "kid": "k", "token": "hex:deadbeef" }
  ]
}"#;
        std::io::Write::write_all(&mut file, json.as_bytes()).unwrap();
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(file.path(), perms).unwrap();
        let store = TokenStore::load(file.path()).unwrap();
        assert!(store.get("k").is_some());
    }
}
