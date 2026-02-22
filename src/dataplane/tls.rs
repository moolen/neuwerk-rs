use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use x509_parser::extensions::GeneralName;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::X509Certificate;
use x509_parser::parse_x509_certificate;

#[derive(Debug, Clone, Default)]
pub struct TlsObservation {
    pub client_hello_seen: bool,
    pub server_hello_seen: bool,
    pub certificate_seen: bool,
    pub tls13: bool,
    pub sni: Option<String>,
    pub cert_chain: Option<TlsCertChain>,
}

#[derive(Debug, Clone)]
pub struct TlsCertChain {
    pub der_chain: Vec<Vec<u8>>,
    pub leaf_san: Vec<String>,
    pub leaf_cn: Vec<String>,
    pub leaf_fingerprint: [u8; 32],
}

impl TlsCertChain {
    pub fn from_der_chain(der_chain: Vec<Vec<u8>>) -> Result<Self, TlsParseError> {
        let leaf_der = der_chain
            .first()
            .ok_or(TlsParseError::InvalidCertificate)?
            .as_slice();
        let (_, cert) =
            parse_x509_certificate(leaf_der).map_err(|_| TlsParseError::InvalidCertificate)?;

        let mut leaf_san = Vec::new();
        for ext in cert.iter_extensions() {
            if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                for name in &san.general_names {
                    if let GeneralName::DNSName(dns) = name {
                        leaf_san.push(normalize_hostname(dns));
                    }
                }
            }
        }

        let mut leaf_cn = Vec::new();
        for cn in cert.subject().iter_common_name() {
            if let Ok(value) = cn.as_str() {
                let normalized = normalize_hostname(value);
                if !normalized.is_empty() {
                    leaf_cn.push(normalized);
                }
            }
        }

        let mut hasher = Sha256::new();
        hasher.update(leaf_der);
        let digest = hasher.finalize();
        let mut leaf_fingerprint = [0u8; 32];
        leaf_fingerprint.copy_from_slice(&digest);

        Ok(Self {
            der_chain,
            leaf_san,
            leaf_cn,
            leaf_fingerprint,
        })
    }
}

#[derive(Debug)]
pub enum TlsParseError {
    InvalidRecord,
    InvalidHandshake,
    InvalidCertificate,
    ReassemblyExceeded,
    ReassemblyGap,
}

#[derive(Debug, Clone, Copy)]
pub enum TlsDirection {
    ClientToServer,
    ServerToClient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsFlowDecision {
    Pending,
    Allowed,
    Denied,
}

#[derive(Debug)]
pub struct TlsFlowState {
    pub observation: TlsObservation,
    pub decision: TlsFlowDecision,
    client_reassembly: TcpReassembly,
    server_reassembly: TcpReassembly,
    client_parser: TlsParser,
    server_parser: TlsParser,
}

impl TlsFlowState {
    pub fn new() -> Self {
        Self {
            observation: TlsObservation::default(),
            decision: TlsFlowDecision::Pending,
            client_reassembly: TcpReassembly::new(),
            server_reassembly: TcpReassembly::new(),
            client_parser: TlsParser::new(),
            server_parser: TlsParser::new(),
        }
    }

    pub fn ingest(
        &mut self,
        direction: TlsDirection,
        seq: u32,
        syn: bool,
        payload: &[u8],
    ) -> Result<TlsIngestResult, TlsParseError> {
        let (reassembly, parser) = match direction {
            TlsDirection::ClientToServer => (&mut self.client_reassembly, &mut self.client_parser),
            TlsDirection::ServerToClient => (&mut self.server_reassembly, &mut self.server_parser),
        };

        let data = reassembly
            .ingest(seq, syn, payload)
            .map_err(|_| TlsParseError::ReassemblyExceeded)?;
        if data.is_empty() {
            return Ok(TlsIngestResult::default());
        }
        let output = parser.ingest(&data)?;
        for event in output.events {
            match event {
                TlsEvent::ClientHello { sni } => {
                    self.observation.client_hello_seen = true;
                    self.observation.sni = sni.as_deref().map(normalize_hostname);
                }
                TlsEvent::ServerHello { tls13 } => {
                    self.observation.server_hello_seen = true;
                    self.observation.tls13 = tls13;
                }
                TlsEvent::Certificate { certs } => {
                    self.observation.certificate_seen = true;
                    if self.observation.cert_chain.is_none() {
                        let chain = TlsCertChain::from_der_chain(certs)?;
                        self.observation.cert_chain = Some(chain);
                    }
                }
            }
        }
        Ok(TlsIngestResult {
            saw_application_data: output.saw_application_data,
        })
    }
}

#[derive(Debug, Default)]
pub struct TlsIngestResult {
    pub saw_application_data: bool,
}

#[derive(Debug)]
struct TlsParser {
    record_buf: Vec<u8>,
    handshake_buf: Vec<u8>,
}

impl TlsParser {
    fn new() -> Self {
        Self {
            record_buf: Vec::new(),
            handshake_buf: Vec::new(),
        }
    }

    fn ingest(&mut self, data: &[u8]) -> Result<TlsParseOutput, TlsParseError> {
        self.record_buf.extend_from_slice(data);
        let mut output = TlsParseOutput::default();

        loop {
            if self.record_buf.len() < 5 {
                break;
            }
            let len = u16::from_be_bytes([self.record_buf[3], self.record_buf[4]]) as usize;
            if self.record_buf.len() < 5 + len {
                break;
            }
            let content_type = self.record_buf[0];
            let payload = &self.record_buf[5..5 + len];
            match content_type {
                22 => {
                    self.handshake_buf.extend_from_slice(payload);
                    self.parse_handshake(&mut output)?;
                }
                23 => output.saw_application_data = true,
                _ => {}
            }
            self.record_buf.drain(0..5 + len);
        }

        Ok(output)
    }

    fn parse_handshake(&mut self, output: &mut TlsParseOutput) -> Result<(), TlsParseError> {
        loop {
            if self.handshake_buf.len() < 4 {
                break;
            }
            let msg_len = ((self.handshake_buf[1] as usize) << 16)
                | ((self.handshake_buf[2] as usize) << 8)
                | (self.handshake_buf[3] as usize);
            if self.handshake_buf.len() < 4 + msg_len {
                break;
            }
            let msg_type = self.handshake_buf[0];
            let body = &self.handshake_buf[4..4 + msg_len];
            match msg_type {
                1 => {
                    let sni = parse_client_hello(body)?;
                    output.events.push(TlsEvent::ClientHello { sni });
                }
                2 => {
                    let tls13 = parse_server_hello(body)?;
                    output.events.push(TlsEvent::ServerHello { tls13 });
                }
                11 => {
                    let certs = parse_certificate(body)?;
                    output.events.push(TlsEvent::Certificate { certs });
                }
                _ => {}
            }
            self.handshake_buf.drain(0..4 + msg_len);
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
struct TlsParseOutput {
    events: Vec<TlsEvent>,
    saw_application_data: bool,
}

#[derive(Debug)]
enum TlsEvent {
    ClientHello { sni: Option<String> },
    ServerHello { tls13: bool },
    Certificate { certs: Vec<Vec<u8>> },
}

fn parse_client_hello(body: &[u8]) -> Result<Option<String>, TlsParseError> {
    let mut idx = 0;
    if body.len() < 2 + 32 + 1 {
        return Err(TlsParseError::InvalidHandshake);
    }
    idx += 2 + 32;
    let session_len = body[idx] as usize;
    idx += 1;
    if idx + session_len > body.len() {
        return Err(TlsParseError::InvalidHandshake);
    }
    idx += session_len;
    if idx + 2 > body.len() {
        return Err(TlsParseError::InvalidHandshake);
    }
    let cipher_len = u16::from_be_bytes([body[idx], body[idx + 1]]) as usize;
    idx += 2;
    if idx + cipher_len > body.len() {
        return Err(TlsParseError::InvalidHandshake);
    }
    idx += cipher_len;
    if idx + 1 > body.len() {
        return Err(TlsParseError::InvalidHandshake);
    }
    let comp_len = body[idx] as usize;
    idx += 1;
    if idx + comp_len > body.len() {
        return Err(TlsParseError::InvalidHandshake);
    }
    idx += comp_len;
    if idx == body.len() {
        return Ok(None);
    }
    if idx + 2 > body.len() {
        return Err(TlsParseError::InvalidHandshake);
    }
    let ext_len = u16::from_be_bytes([body[idx], body[idx + 1]]) as usize;
    idx += 2;
    if idx + ext_len > body.len() {
        return Err(TlsParseError::InvalidHandshake);
    }
    let ext_end = idx + ext_len;
    while idx + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[idx], body[idx + 1]]);
        let len = u16::from_be_bytes([body[idx + 2], body[idx + 3]]) as usize;
        idx += 4;
        if idx + len > ext_end {
            return Err(TlsParseError::InvalidHandshake);
        }
        if ext_type == 0x0000 {
            if len < 2 {
                return Err(TlsParseError::InvalidHandshake);
            }
            let mut pos = idx;
            let list_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
            pos += 2;
            if pos + list_len > idx + len {
                return Err(TlsParseError::InvalidHandshake);
            }
            while pos + 3 <= idx + len {
                let name_type = body[pos];
                let name_len = u16::from_be_bytes([body[pos + 1], body[pos + 2]]) as usize;
                pos += 3;
                if pos + name_len > idx + len {
                    return Err(TlsParseError::InvalidHandshake);
                }
                if name_type == 0 {
                    let name =
                        std::str::from_utf8(&body[pos..pos + name_len]).map_err(|_| {
                            TlsParseError::InvalidHandshake
                        })?;
                    return Ok(Some(name.to_string()));
                }
                pos += name_len;
            }
        }
        idx += len;
    }
    Ok(None)
}

fn parse_server_hello(body: &[u8]) -> Result<bool, TlsParseError> {
    let mut idx = 0;
    if body.len() < 2 + 32 + 1 {
        return Err(TlsParseError::InvalidHandshake);
    }
    idx += 2 + 32;
    let session_len = body[idx] as usize;
    idx += 1;
    if idx + session_len > body.len() {
        return Err(TlsParseError::InvalidHandshake);
    }
    idx += session_len;
    if idx + 2 + 1 > body.len() {
        return Err(TlsParseError::InvalidHandshake);
    }
    idx += 2 + 1;
    if idx == body.len() {
        return Ok(false);
    }
    if idx + 2 > body.len() {
        return Err(TlsParseError::InvalidHandshake);
    }
    let ext_len = u16::from_be_bytes([body[idx], body[idx + 1]]) as usize;
    idx += 2;
    if idx + ext_len > body.len() {
        return Err(TlsParseError::InvalidHandshake);
    }
    let ext_end = idx + ext_len;
    let mut tls13 = false;
    while idx + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[idx], body[idx + 1]]);
        let len = u16::from_be_bytes([body[idx + 2], body[idx + 3]]) as usize;
        idx += 4;
        if idx + len > ext_end {
            return Err(TlsParseError::InvalidHandshake);
        }
        if ext_type == 0x002b && len == 2 {
            let selected = u16::from_be_bytes([body[idx], body[idx + 1]]);
            if selected == 0x0304 {
                tls13 = true;
            }
        }
        idx += len;
    }
    Ok(tls13)
}

fn parse_certificate(body: &[u8]) -> Result<Vec<Vec<u8>>, TlsParseError> {
    if body.len() < 3 {
        return Err(TlsParseError::InvalidHandshake);
    }
    let list_len = ((body[0] as usize) << 16) | ((body[1] as usize) << 8) | body[2] as usize;
    if 3 + list_len > body.len() {
        return Err(TlsParseError::InvalidHandshake);
    }
    let mut idx = 3;
    let end = 3 + list_len;
    let mut certs = Vec::new();
    while idx + 3 <= end {
        let cert_len =
            ((body[idx] as usize) << 16) | ((body[idx + 1] as usize) << 8) | body[idx + 2] as usize;
        idx += 3;
        if idx + cert_len > end {
            return Err(TlsParseError::InvalidHandshake);
        }
        certs.push(body[idx..idx + cert_len].to_vec());
        idx += cert_len;
    }
    if certs.is_empty() {
        return Err(TlsParseError::InvalidHandshake);
    }
    Ok(certs)
}

#[derive(Debug)]
pub struct TlsVerifier {
    system_anchors: Vec<Vec<u8>>,
}

impl TlsVerifier {
    pub fn new() -> Self {
        let mut anchors = Vec::new();
        if let Ok(store) = rustls_native_certs::load_native_certs() {
            for cert in store {
                anchors.push(cert.as_ref().to_vec());
            }
        }
        Self {
            system_anchors: anchors,
        }
    }

    pub fn verify_chain(&self, chain: &TlsCertChain, extra_anchors: &[Vec<u8>]) -> bool {
        let mut anchors = Vec::with_capacity(self.system_anchors.len() + extra_anchors.len());
        anchors.extend(self.system_anchors.iter().cloned());
        anchors.extend(extra_anchors.iter().cloned());

        let mut chain_parsed = Vec::with_capacity(chain.der_chain.len());
        for der in &chain.der_chain {
            let (_, cert) = match parse_x509_certificate(der) {
                Ok(value) => value,
                Err(_) => return false,
            };
            chain_parsed.push(cert);
        }
        if chain_parsed.is_empty() {
            return false;
        }

        let mut anchors_parsed = Vec::new();
        for der in &anchors {
            if let Ok((_, cert)) = parse_x509_certificate(der) {
                anchors_parsed.push(cert);
            }
        }
        if anchors_parsed.is_empty() {
            return false;
        }

        for idx in 0..chain_parsed.len() {
            let cert = &chain_parsed[idx];
            if idx + 1 < chain_parsed.len() {
                let issuer = &chain_parsed[idx + 1];
                if !names_match(cert.issuer(), issuer.subject()) {
                    return false;
                }
                if !is_ca_cert(issuer) {
                    return false;
                }
                if cert.verify_signature(Some(issuer.public_key())).is_err() {
                    return false;
                }
            } else {
                let mut verified = false;
                for anchor in &anchors_parsed {
                    if !is_ca_cert(anchor) {
                        continue;
                    }
                    if !names_match(cert.issuer(), anchor.subject()) {
                        continue;
                    }
                    if cert.verify_signature(Some(anchor.public_key())).is_ok() {
                        verified = true;
                        break;
                    }
                }
                if !verified {
                    return false;
                }
            }
        }

        true
    }
}

fn names_match(a: &x509_parser::x509::X509Name<'_>, b: &x509_parser::x509::X509Name<'_>) -> bool {
    a == b
}

fn is_ca_cert(cert: &X509Certificate<'_>) -> bool {
    for ext in cert.iter_extensions() {
        if let ParsedExtension::BasicConstraints(constraints) = ext.parsed_extension() {
            return constraints.ca;
        }
    }
    true
}

#[derive(Debug)]
struct TcpReassembly {
    expected_seq: Option<u32>,
    segments: BTreeMap<u32, Vec<u8>>,
    buffered_bytes: usize,
    started: bool,
}

impl TcpReassembly {
    const MAX_BYTES: usize = 64 * 1024;
    const MAX_SEGMENTS: usize = 32;

    fn new() -> Self {
        Self {
            expected_seq: None,
            segments: BTreeMap::new(),
            buffered_bytes: 0,
            started: false,
        }
    }

    fn ingest(&mut self, seq: u32, syn: bool, payload: &[u8]) -> Result<Vec<u8>, ()> {
        let data_seq = seq.wrapping_add(if syn { 1 } else { 0 });
        if payload.is_empty() {
            self.expected_seq.get_or_insert(data_seq);
            return Ok(Vec::new());
        }

        let mut start_seq = data_seq;
        let mut data = payload;
        if let Some(expected) = self.expected_seq {
            if data_seq < expected && !self.started {
                self.expected_seq = Some(data_seq);
            } else if data_seq < expected {
                let offset = (expected - data_seq) as usize;
                if offset >= payload.len() {
                    return Ok(Vec::new());
                }
                start_seq = expected;
                data = &payload[offset..];
            }
        }

        if self.expected_seq.is_none() {
            self.expected_seq = Some(start_seq);
        }

        let data_vec = data.to_vec();
        if let Some(existing) = self.segments.insert(start_seq, data_vec) {
            self.buffered_bytes = self.buffered_bytes.saturating_sub(existing.len());
        }
        self.buffered_bytes = self.buffered_bytes.saturating_add(data.len());
        if self.buffered_bytes > Self::MAX_BYTES || self.segments.len() > Self::MAX_SEGMENTS {
            return Err(());
        }

        let mut out = Vec::new();
        loop {
            let expected = match self.expected_seq {
                Some(value) => value,
                None => break,
            };
            let segment = match self.segments.remove(&expected) {
                Some(segment) => segment,
                None => break,
            };
            self.buffered_bytes = self.buffered_bytes.saturating_sub(segment.len());
            self.expected_seq = Some(expected.wrapping_add(segment.len() as u32));
            out.extend_from_slice(&segment);
        }
        if !out.is_empty() {
            self.started = true;
        }

        Ok(out)
    }
}

pub fn normalize_hostname(name: &str) -> String {
    name.trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
}
