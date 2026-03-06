import type { DNSCacheResponse } from '../../types';
import { fetchJSON } from './transport';

export async function getDNSCache(): Promise<DNSCacheResponse> {
  return fetchJSON<DNSCacheResponse>('/dns-cache');
}
