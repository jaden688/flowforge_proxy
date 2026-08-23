import { useEffect } from 'react';
import { wsClient } from '../services/websocket';
import { useFlowStore } from '../store/flowStore';

export function useWebSocket() {
  const wsConnected = useFlowStore((s) => s.wsConnected);
  const wsLatencyMs = useFlowStore((s) => s.wsLatencyMs);
  const isPaused = useFlowStore((s) => s.isPaused);
  const setPaused = useFlowStore((s) => s.setPaused);

  useEffect(() => {
    wsClient.connect();
    return () => {
      wsClient.disconnect();
    };
  }, []);

  const togglePause = () => {
    setPaused(!isPaused);
  };

  return {
    wsConnected,
    wsLatencyMs,
    isPaused,
    togglePause,
  };
}
