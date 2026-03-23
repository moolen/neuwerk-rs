import { useEffect, useState } from 'react';

import {
  createThreatSilence,
  deleteThreatSilence,
  listThreatSilences,
} from '../../services/api';
import type { CreateThreatSilenceRequest } from '../../services/apiClient/threats';
import type { ThreatSilenceEntry } from '../../types';
import { sortSilences } from './state';

export function useThreatSilencesPage() {
  const [silences, setSilences] = useState<ThreatSilenceEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [silenceSaving, setSilenceSaving] = useState(false);
  const [deletingSilenceId, setDeletingSilenceId] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);

    try {
      const silenceList = await listThreatSilences();
      setSilences(sortSilences(silenceList.items));
    } catch (err) {
      console.error('Failed to load threat silences:', err);
      setError(err instanceof Error ? err.message : 'Failed to load threat silences');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  useEffect(() => {
    window.history.replaceState(window.history.state, '', '/threats/silences');
  }, []);

  const createSilence = async (request: CreateThreatSilenceRequest) => {
    try {
      setSilenceSaving(true);
      setError(null);
      await createThreatSilence(request);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create threat silence');
      throw err;
    } finally {
      setSilenceSaving(false);
    }
  };

  const removeSilence = async (id: string) => {
    try {
      setDeletingSilenceId(id);
      setError(null);
      await deleteThreatSilence(id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete threat silence');
      throw err;
    } finally {
      setDeletingSilenceId(null);
    }
  };

  return {
    silences,
    loading,
    error,
    deletingSilenceId,
    silenceSaving,
    createSilence,
    deleteSilence: removeSilence,
  };
}
