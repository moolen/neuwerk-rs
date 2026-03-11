import { useEffect, useState } from 'react';

import type { SsoSupportedProvider } from '../../types';
import { listSupportedSsoProviders } from '../../services/api';

export function useSsoProviders() {
  const [providers, setProviders] = useState<SsoSupportedProvider[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;

    const load = async () => {
      try {
        setLoading(true);
        setError(null);
        const next = await listSupportedSsoProviders();
        if (!active) {
          return;
        }
        setProviders(next);
      } catch (err) {
        if (!active) {
          return;
        }
        setProviders([]);
        setError(err instanceof Error ? err.message : 'Failed to load SSO providers');
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    };

    void load();
    return () => {
      active = false;
    };
  }, []);

  return {
    providers,
    loading,
    error,
  };
}
