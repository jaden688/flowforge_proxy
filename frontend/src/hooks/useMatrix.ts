import { useState, useCallback } from 'react';
import { useFlowStore } from '../store/flowStore';
import { api } from '../services/api';
import { TestMatrixJob, TestMatrixCase } from '../types';

export function useMatrix() {
  const activeMatrixJob = useFlowStore((s) => s.activeMatrixJob);
  const setMatrixJob = useFlowStore((s) => s.setMatrixJob);
  const updateMatrixCase = useFlowStore((s) => s.updateMatrixCase);
  const toggleCaseSelected = useFlowStore((s) => s.toggleCaseSelected);
  const toggleAllCasesSelected = useFlowStore((s) => s.toggleAllCasesSelected);
  const flows = useFlowStore((s) => s.flows);

  const [isGenerating, setIsGenerating] = useState(false);
  const [isExecuting, setIsExecuting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const generateMatrixForFlow = useCallback(async (
    flowId: string,
    categories?: string[]
  ) => {
    setIsGenerating(true);
    setError(null);
    try {
      const flow = flows[flowId];
      const job = await api.generateMatrix({
        flow_id: flowId,
        endpoint_path: flow?.path,
        method: flow?.method,
        categories,
      });
      setMatrixJob(job);
      return job;
    } catch (err: any) {
      setError(err.message || 'Failed to generate test matrix');
      return null;
    } finally {
      setIsGenerating(false);
    }
  }, [flows, setMatrixJob]);

  const generateMatrixForEndpoint = useCallback(async (
    endpointPath: string,
    method = 'GET',
    categories?: string[]
  ) => {
    setIsGenerating(true);
    setError(null);
    try {
      const job = await api.generateMatrix({
        endpoint_path: endpointPath,
        method,
        categories,
      });
      setMatrixJob(job);
      return job;
    } catch (err: any) {
      setError(err.message || 'Failed to generate test matrix');
      return null;
    } finally {
      setIsGenerating(false);
    }
  }, [setMatrixJob]);

  const executeSelectedTests = useCallback(async (concurrency = 2) => {
    if (!activeMatrixJob) return;
    const selectedCases = activeMatrixJob.cases.filter((c) => c.selected);
    if (!selectedCases.length) {
      setError('Please select at least one test case to execute');
      return;
    }

    setIsExecuting(true);
    setError(null);

    try {
      setMatrixJob({
        ...activeMatrixJob,
        is_running: true,
        cases: activeMatrixJob.cases.map((c) =>
          c.selected ? { ...c, status: 'QUEUED' } : c
        ),
      });

      await api.executeMatrix({
        job_id: activeMatrixJob.job_id,
        case_ids: selectedCases.map((c) => c.id),
        concurrency,
      });

      // Poll periodically or let WebSocket update it
      const pollInterval = setInterval(async () => {
        try {
          const updated = await api.getMatrixJob(activeMatrixJob.job_id);
          setMatrixJob(updated);
          if (!updated.is_running) {
            clearInterval(pollInterval);
            setIsExecuting(false);
          }
        } catch {
          clearInterval(pollInterval);
          setIsExecuting(false);
        }
      }, 1000);
    } catch (err: any) {
      setError(err.message || 'Failed to execute test matrix');
      setIsExecuting(false);
    }
  }, [activeMatrixJob, setMatrixJob]);

  return {
    job: activeMatrixJob,
    isGenerating,
    isExecuting,
    error,
    generateMatrixForFlow,
    generateMatrixForEndpoint,
    executeSelectedTests,
    updateMatrixCase,
    toggleCaseSelected,
    toggleAllCasesSelected,
  };
}
