import { useState, useEffect, useCallback } from 'react';
import { useFlowStore } from '../store/flowStore';
import { api } from '../services/api';
import { FlowComparisonResult, FlowRecord } from '../types';

export function useDiff() {
  const diffFlowAId = useFlowStore((s) => s.diffFlowAId);
  const diffFlowBId = useFlowStore((s) => s.diffFlowBId);
  const flows = useFlowStore((s) => s.flows);
  const setDiffPair = useFlowStore((s) => s.setDiffPair);

  const [comparisonResult, setComparisonResult] = useState<FlowComparisonResult | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [diffMode, setDiffMode] = useState<'sideBySide' | 'unified'>('sideBySide');
  const [diffScope, setDiffScope] = useState<'all' | 'request' | 'response' | 'body' | 'headers'>('all');

  const executeDiff = useCallback(async (idA?: string | null, idB?: string | null) => {
    const targetA = idA !== undefined ? idA : diffFlowAId;
    const targetB = idB !== undefined ? idB : diffFlowBId;

    setIsLoading(true);
    setError(null);

    try {
      const flowA = targetA ? flows[targetA] : undefined;
      const flowB = targetB ? flows[targetB] : undefined;

      const result = await api.computeDiff({
        flow_id_a: targetA || undefined,
        flow_id_b: targetB || undefined,
        flow_a: flowA,
        flow_b: flowB,
      });

      setComparisonResult(result);
    } catch (err: any) {
      setError(err.message || 'Failed to compute diff');
    } finally {
      setIsLoading(false);
    }
  }, [diffFlowAId, diffFlowBId, flows]);

  useEffect(() => {
    if (diffFlowAId || diffFlowBId) {
      executeDiff();
    }
  }, [diffFlowAId, diffFlowBId, executeDiff]);

  const swapFlows = () => {
    setDiffPair(diffFlowBId, diffFlowAId);
  };

  const setFlowA = (id: string | null) => {
    setDiffPair(id, diffFlowBId);
  };

  const setFlowB = (id: string | null) => {
    setDiffPair(diffFlowAId, id);
  };

  return {
    flowAId: diffFlowAId,
    flowBId: diffFlowBId,
    flowA: diffFlowAId ? flows[diffFlowAId] : null,
    flowB: diffFlowBId ? flows[diffFlowBId] : null,
    comparisonResult,
    isLoading,
    error,
    diffMode,
    setDiffMode,
    diffScope,
    setDiffScope,
    executeDiff,
    swapFlows,
    setFlowA,
    setFlowB,
  };
}
