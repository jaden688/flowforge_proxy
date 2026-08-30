import { useState, useCallback, useEffect, useRef } from 'react';
import { useFlowStore } from '../store/flowStore';
import { api } from '../services/api';
import { IntruderJob, IntruderJobConfig, CustomWordlist, ArsenalWordlist } from '../types';

export function useIntruder() {
  const activeIntruderJob = useFlowStore((s) => s.activeIntruderJob);
  const intruderResults = useFlowStore((s) => s.intruderResults);
  const intruderResultFilters = useFlowStore((s) => s.intruderResultFilters);
  const setActiveIntruderJob = useFlowStore((s) => s.setActiveIntruderJob);
  const clearResults = useFlowStore((s) => s.clearIntruderResults);

  const [isLaunching, setIsLaunching] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<number | null>(null);

  // Poll job state as a safety net alongside WebSocket status events.
  useEffect(() => {
    if (!activeIntruderJob || (activeIntruderJob.status !== 'RUNNING' && activeIntruderJob.status !== 'PENDING')) {
      return;
    }
    const jobId = activeIntruderJob.id;
    pollRef.current = window.setInterval(async () => {
      try {
        const fresh = await api.getIntruderJob(jobId);
        const current = useFlowStore.getState().activeIntruderJob;
        if (current && current.id === jobId) {
          setActiveIntruderJob(fresh);
        }
      } catch {
        // transient; WS events usually keep UI updated anyway
      }
    }, 2000);
    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    };
  }, [activeIntruderJob?.id, activeIntruderJob?.status, setActiveIntruderJob]);

  const launchJob = useCallback(async (config: IntruderJobConfig): Promise<IntruderJob | null> => {
    setIsLaunching(true);
    setError(null);
    try {
      const job = await api.createIntruderJob(config);
      setActiveIntruderJob(job);
      return job;
    } catch (err: any) {
      setError(err.message || 'Failed to launch intruder job');
      return null;
    } finally {
      setIsLaunching(false);
    }
  }, [setActiveIntruderJob]);

  const abortJob = useCallback(async (jobId?: string) => {
    const id = jobId ?? useFlowStore.getState().activeIntruderJob?.id;
    if (!id) return;
    try {
      await api.abortIntruderJob(id);
      const current = useFlowStore.getState().activeIntruderJob;
      if (current && current.id === id) {
        setActiveIntruderJob({ ...current, status: 'ABORTED' });
      }
    } catch (err: any) {
      setError(err.message || 'Failed to abort job');
    }
  }, [setActiveIntruderJob]);

  const refreshResults = useCallback(async (jobId?: string) => {
    const id = jobId ?? useFlowStore.getState().activeIntruderJob?.id;
    if (!id) return;
    try {
      const data = await api.getIntruderResults(id, { limit: 5000 });
      // Replace live buffer with authoritative server-side filtered set.
      useFlowStore.setState({
        intruderResults: applyFilters(data.items, useFlowStore.getState().intruderResultFilters),
      });
    } catch {
      // ignore
    }
  }, []);

  return {
    activeIntruderJob,
    intruderResults,
    intruderResultFilters,
    isLaunching,
    error,
    launchJob,
    abortJob,
    refreshResults,
    setActiveIntruderJob,
    clearResults,
  };
}

function applyFilters<T>(items: T[], _filters: unknown): T[] {
  // Server already applied persisted filters for the REST fetch; the store's
  // addIntruderResult applies them for streamed rows.
  return items;
}
