import { useEffect, useState } from 'react';
import { getStats } from '../../services/api';
import type { StatsResponse } from '../../types';

export function useDashboardStats() {
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const data = await getStats();
        setStats(data);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch stats');
      } finally {
        setLoading(false);
      }
    };

    void fetchStats();
    const interval = setInterval(() => {
      void fetchStats();
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  return {
    stats,
    error,
    loading,
  };
}
