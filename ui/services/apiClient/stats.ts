import type { StatsResponse } from '../../types';
import { fetchJSON } from './transport';

export async function getStats(): Promise<StatsResponse> {
  return fetchJSON<StatsResponse>('/stats');
}
