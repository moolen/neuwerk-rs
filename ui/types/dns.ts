export interface DNSCacheEntry {
  hostname: string;
  ips: string[];
  last_seen: number;
}

export interface DNSCacheResponse {
  entries: DNSCacheEntry[];
}
