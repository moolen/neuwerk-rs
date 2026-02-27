use firewall::dataplane::tls::{TlsDirection, TlsFlowState, TlsVerifier};
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyUsagePurpose};

fn tls_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(content_type);
    out.extend_from_slice(&0x0303u16.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn handshake_message(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(msg_type);
    out.push(((body.len() >> 16) & 0xff) as u8);
    out.push(((body.len() >> 8) & 0xff) as u8);
    out.push((body.len() & 0xff) as u8);
    out.extend_from_slice(body);
    out
}

fn client_hello_body(sni: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&0x1301u16.to_be_bytes());
    body.push(1);
    body.push(0);

    let sni_bytes = sni.as_bytes();
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&((sni_bytes.len() + 3) as u16).to_be_bytes());
    sni_ext.push(0);
    sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(sni_bytes);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0u16.to_be_bytes());
    extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_ext);

    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    body
}

fn server_hello_body_tls13() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&0x1301u16.to_be_bytes());
    body.push(0);

    let mut ext = Vec::new();
    ext.extend_from_slice(&0x002bu16.to_be_bytes());
    ext.extend_from_slice(&2u16.to_be_bytes());
    ext.extend_from_slice(&0x0304u16.to_be_bytes());

    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    body
}

fn certificate_body(certs: &[Vec<u8>]) -> Vec<u8> {
    let mut list = Vec::new();
    for cert in certs {
        let len = cert.len();
        list.push(((len >> 16) & 0xff) as u8);
        list.push(((len >> 8) & 0xff) as u8);
        list.push((len & 0xff) as u8);
        list.extend_from_slice(cert);
    }
    let mut body = Vec::new();
    body.push(((list.len() >> 16) & 0xff) as u8);
    body.push(((list.len() >> 8) & 0xff) as u8);
    body.push((list.len() & 0xff) as u8);
    body.extend_from_slice(&list);
    body
}

#[test]
fn tls_client_hello_sni_extracted() {
    let hello = client_hello_body("api.example.com");
    let handshake = handshake_message(1, &hello);
    let record = tls_record(22, &handshake);

    let mut tls = TlsFlowState::new();
    tls.ingest(TlsDirection::ClientToServer, 0, true, &record)
        .unwrap();

    assert!(tls.observation.client_hello_seen);
    assert_eq!(tls.observation.sni.as_deref(), Some("api.example.com"));
}

#[test]
fn tls_server_hello_tls13_detected() {
    let hello = server_hello_body_tls13();
    let handshake = handshake_message(2, &hello);
    let record = tls_record(22, &handshake);

    let mut tls = TlsFlowState::new();
    tls.ingest(TlsDirection::ServerToClient, 0, true, &record)
        .unwrap();

    assert!(tls.observation.server_hello_seen);
    assert!(tls.observation.tls13);
}

#[test]
fn tls_certificate_chain_parsed_and_verified() {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Test CA");
    let ca_cert = Certificate::from_params(ca_params).unwrap();
    let ca_der = ca_cert.serialize_der().unwrap();

    let mut leaf_params = CertificateParams::new(vec!["example.com".to_string()]);
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "example.com");
    let leaf_cert = Certificate::from_params(leaf_params).unwrap();
    let leaf_der = leaf_cert.serialize_der_with_signer(&ca_cert).unwrap();

    let body = certificate_body(&[leaf_der.clone(), ca_der.clone()]);
    let handshake = handshake_message(11, &body);
    let record = tls_record(22, &handshake);

    let mut tls = TlsFlowState::new();
    tls.ingest(TlsDirection::ServerToClient, 0, true, &record)
        .unwrap();

    let chain = tls.observation.cert_chain.as_ref().unwrap();
    assert!(chain.leaf_cn.iter().any(|cn| cn == "example.com"));
    assert!(chain.leaf_san.iter().any(|san| san == "example.com"));

    let verifier = TlsVerifier::new();
    assert!(verifier.verify_chain(chain, &[ca_der]));
}

#[test]
fn tls_client_hello_reassembles_across_segments() {
    let hello = client_hello_body("Api.Example.Com.");
    let handshake = handshake_message(1, &hello);
    let record = tls_record(22, &handshake);

    let split = record.len() / 2;
    let part1 = &record[..split];
    let part2 = &record[split..];

    let mut tls = TlsFlowState::new();
    tls.ingest(TlsDirection::ClientToServer, 0, true, part1)
        .unwrap();
    assert!(!tls.observation.client_hello_seen);

    let seq = 1 + part1.len() as u32;
    tls.ingest(TlsDirection::ClientToServer, seq, false, part2)
        .unwrap();

    assert!(tls.observation.client_hello_seen);
    assert_eq!(tls.observation.sni.as_deref(), Some("api.example.com"));
}

#[test]
fn tls_client_hello_reassembles_out_of_order_after_syn() {
    let hello = client_hello_body("api.example.com");
    let handshake = handshake_message(1, &hello);
    let record = tls_record(22, &handshake);

    let split = record.len() / 2;
    let part1 = &record[..split];
    let part2 = &record[split..];

    let mut tls = TlsFlowState::new();
    tls.ingest(TlsDirection::ClientToServer, 0, true, &[])
        .unwrap();

    let seq2 = 1 + part1.len() as u32;
    tls.ingest(TlsDirection::ClientToServer, seq2, false, part2)
        .unwrap();
    assert!(!tls.observation.client_hello_seen);

    tls.ingest(TlsDirection::ClientToServer, 1, false, part1)
        .unwrap();
    assert!(tls.observation.client_hello_seen);
    assert_eq!(tls.observation.sni.as_deref(), Some("api.example.com"));
}

#[test]
fn tls_certificate_reassembles_across_segments() {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Reassembly CA");
    let ca_cert = Certificate::from_params(ca_params).unwrap();
    let ca_der = ca_cert.serialize_der().unwrap();

    let mut leaf_params = CertificateParams::new(vec!["foo.allowed".to_string()]);
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "foo.allowed");
    let leaf_cert = Certificate::from_params(leaf_params).unwrap();
    let leaf_der = leaf_cert.serialize_der_with_signer(&ca_cert).unwrap();

    let body = certificate_body(&[leaf_der, ca_der]);
    let handshake = handshake_message(11, &body);
    let record = tls_record(22, &handshake);

    let split = record.len() / 3;
    let part1 = &record[..split];
    let part2 = &record[split..];

    let mut tls = TlsFlowState::new();
    tls.ingest(TlsDirection::ServerToClient, 0, true, part1)
        .unwrap();
    assert!(!tls.observation.certificate_seen);

    let seq = 1 + part1.len() as u32;
    tls.ingest(TlsDirection::ServerToClient, seq, false, part2)
        .unwrap();

    assert!(tls.observation.certificate_seen);
    assert!(tls.observation.cert_chain.is_some());
}

#[test]
fn tls_reassembly_limit_exceeded_errors() {
    let payload = vec![0u8; 64 * 1024 + 1];
    let mut tls = TlsFlowState::new();
    let result = tls.ingest(TlsDirection::ClientToServer, 0, true, &payload);
    assert!(result.is_err());
}
