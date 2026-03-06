use super::*;

#[derive(Debug, Deserialize)]
pub struct AuthUser {
    pub sub: String,
    pub sa_id: Option<String>,
    pub exp: Option<i64>,
    pub roles: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct DnsCacheEntry {
    pub hostname: String,
    pub ips: Vec<Ipv4Addr>,
    pub last_seen: u64,
}

#[derive(Debug, Deserialize)]
pub struct DnsCacheResponse {
    pub entries: Vec<DnsCacheEntry>,
}
