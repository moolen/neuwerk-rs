use std::collections::HashMap;
use std::fs;
use std::path::Path;

use base64::Engine;
use serde::Deserialize;
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
    valid_until: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedToken {
    pub kid: String,
    pub token: Vec<u8>,
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
    #[error("invalid valid_until for kid {0}")]
    InvalidValidUntil(String),
    #[error("no valid tokens found")]
    NoValidTokens,
}

impl TokenStore {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, TokenError> {
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
            let valid_until = match entry.valid_until {
                Some(raw) => Some(
                    OffsetDateTime::parse(&raw, &Rfc3339)
                        .map_err(|_| TokenError::InvalidValidUntil(entry.kid.clone()))?,
                ),
                None => None,
            };

            tokens.insert(
                entry.kid.clone(),
                ParsedToken {
                    kid: entry.kid,
                    token,
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
            if let Some(until) = token.valid_until {
                if until < now {
                    continue;
                }
            }

            best = match best {
                None => Some(token),
                Some(existing) => match (token.valid_until, existing.valid_until) {
                    (Some(a), Some(b)) => {
                        if a > b {
                            Some(token)
                        } else {
                            Some(existing)
                        }
                    }
                    (Some(_), None) => Some(existing),
                    (None, Some(_)) => Some(token),
                    (None, None) => Some(existing),
                },
            };
        }

        best.ok_or(TokenError::NoValidTokens)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn parses_and_selects_current_token() {
        let mut file = NamedTempFile::new().unwrap();
        let json = r#"{
  "tokens": [
    { "kid": "old", "token": "hex:deadbeef", "valid_until": "2026-01-01T00:00:00Z" },
    { "kid": "new", "token": "b64:Zm9vYmFy", "valid_until": "2026-12-01T00:00:00Z" }
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
}
