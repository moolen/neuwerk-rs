#![no_main]

use firewall::dataplane::tls::{TlsDirection, TlsFlowState};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut state = TlsFlowState::new();
    let mut idx = 0usize;
    let mut client_seq = 0u32;
    let mut server_seq = 0u32;

    while idx < data.len() {
        let dir = if data[idx] & 1 == 0 {
            TlsDirection::ClientToServer
        } else {
            TlsDirection::ServerToClient
        };
        idx += 1;

        if idx >= data.len() {
            break;
        }
        let syn = data[idx] & 1 == 1;
        idx += 1;

        if idx >= data.len() {
            break;
        }
        let chunk_len = (data[idx] as usize) % 96;
        idx += 1;

        let end = (idx + chunk_len).min(data.len());
        let chunk = &data[idx..end];
        idx = end;

        let seq = match dir {
            TlsDirection::ClientToServer => client_seq,
            TlsDirection::ServerToClient => server_seq,
        };
        let _ = state.ingest(dir, seq, syn, chunk);
        match dir {
            TlsDirection::ClientToServer => {
                client_seq = client_seq.wrapping_add(chunk.len() as u32);
            }
            TlsDirection::ServerToClient => {
                server_seq = server_seq.wrapping_add(chunk.len() as u32);
            }
        }
    }
});
