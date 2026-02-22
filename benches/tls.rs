use criterion::{black_box, criterion_group, criterion_main, Criterion};
use firewall::dataplane::tls::{TlsDirection, TlsFlowState};
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

fn generate_cert_chain() -> Vec<Vec<u8>> {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Bench CA");
    let ca_cert = Certificate::from_params(ca_params).unwrap();
    let ca_der = ca_cert.serialize_der().unwrap();

    let mut leaf_params = CertificateParams::new(vec!["bench.example".to_string()]);
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "bench.example");
    let leaf_cert = Certificate::from_params(leaf_params).unwrap();
    let leaf_der = leaf_cert.serialize_der_with_signer(&ca_cert).unwrap();

    vec![leaf_der, ca_der]
}

fn bench_tls_client_hello(c: &mut Criterion) {
    let hello = client_hello_body("api.example.com");
    let handshake = handshake_message(1, &hello);
    let record = tls_record(22, &handshake);

    c.bench_function("tls_ingest_client_hello", |b| {
        b.iter(|| {
            let mut tls = TlsFlowState::new();
            tls.ingest(
                TlsDirection::ClientToServer,
                0,
                true,
                black_box(&record),
            )
            .unwrap();
        })
    });
}

fn bench_tls_certificate_chain(c: &mut Criterion) {
    let chain = generate_cert_chain();
    let body = certificate_body(&chain);
    let handshake = handshake_message(11, &body);
    let record = tls_record(22, &handshake);

    c.bench_function("tls_ingest_certificate_chain", |b| {
        b.iter(|| {
            let mut tls = TlsFlowState::new();
            tls.ingest(
                TlsDirection::ServerToClient,
                0,
                true,
                black_box(&record),
            )
            .unwrap();
        })
    });
}

fn bench_tls_reassembly_split(c: &mut Criterion) {
    let hello = client_hello_body("api.example.com");
    let handshake = handshake_message(1, &hello);
    let record = tls_record(22, &handshake);
    let split = record.len() / 2;
    let part1 = record[..split].to_vec();
    let part2 = record[split..].to_vec();

    c.bench_function("tls_ingest_reassembly_split", |b| {
        b.iter(|| {
            let mut tls = TlsFlowState::new();
            tls.ingest(
                TlsDirection::ClientToServer,
                0,
                true,
                black_box(&part1),
            )
            .unwrap();
            let seq = 1 + part1.len() as u32;
            tls.ingest(
                TlsDirection::ClientToServer,
                seq,
                false,
                black_box(&part2),
            )
            .unwrap();
        })
    });
}

criterion_group!(
    tls_benches,
    bench_tls_client_hello,
    bench_tls_certificate_chain,
    bench_tls_reassembly_split
);
criterion_main!(tls_benches);
