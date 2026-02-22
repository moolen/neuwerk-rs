use std::net::Ipv4Addr;

pub const DHCP_CLIENT_PORT: u16 = 68;
pub const DHCP_SERVER_PORT: u16 = 67;

#[derive(Debug, Clone)]
pub struct DhcpRx {
    pub src_ip: Ipv4Addr,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum DhcpTx {
    Broadcast { payload: Vec<u8> },
    Unicast { payload: Vec<u8>, dst_ip: Ipv4Addr },
}
