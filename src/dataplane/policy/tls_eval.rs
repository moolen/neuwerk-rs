use crate::dataplane::tls::{TlsObservation, TlsVerifier};

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TlsMatchOutcome {
    Match,
    Mismatch,
    Pending,
    Deny,
}

impl TlsMatch {
    pub(super) fn evaluate(&self, obs: &TlsObservation, verifier: &TlsVerifier) -> TlsMatchOutcome {
        if matches!(self.mode, TlsMode::Intercept) {
            // Intercept mode is handled in policy evaluation before metadata checks.
            return TlsMatchOutcome::Match;
        }

        if let Some(sni) = &self.sni {
            if !obs.client_hello_seen {
                return TlsMatchOutcome::Pending;
            }
            match obs.sni.as_deref() {
                Some(value) if sni.is_match(value) => {}
                _ => return TlsMatchOutcome::Mismatch,
            }
        }

        let needs_cert = self.requires_certificate();
        if needs_cert {
            if obs.tls13 {
                return match self.tls13_uninspectable {
                    Tls13Uninspectable::Allow => TlsMatchOutcome::Match,
                    Tls13Uninspectable::Deny => TlsMatchOutcome::Deny,
                };
            }

            if !obs.certificate_seen {
                return TlsMatchOutcome::Pending;
            }

            let Some(chain) = &obs.cert_chain else {
                return TlsMatchOutcome::Deny;
            };

            if !verifier.verify_chain(chain, &self.trust_anchors) {
                return TlsMatchOutcome::Deny;
            }

            if let Some(server_san) = &self.server_san {
                if !chain
                    .leaf_san
                    .iter()
                    .any(|value| server_san.is_match(value))
                {
                    return TlsMatchOutcome::Mismatch;
                }
            }

            if let Some(server_cn) = &self.server_cn {
                if !chain.leaf_cn.iter().any(|value| server_cn.is_match(value)) {
                    return TlsMatchOutcome::Mismatch;
                }
            }

            if !self.fingerprints_sha256.is_empty()
                && !self
                    .fingerprints_sha256
                    .iter()
                    .any(|fp| fp == &chain.leaf_fingerprint)
            {
                return TlsMatchOutcome::Mismatch;
            }
        }

        TlsMatchOutcome::Match
    }

    fn requires_certificate(&self) -> bool {
        self.server_san.is_some()
            || self.server_cn.is_some()
            || !self.fingerprints_sha256.is_empty()
            || !self.trust_anchors.is_empty()
    }
}
