import React from 'react';
import { TrafficTable } from './TrafficTable';
import { SplitInspector } from './SplitInspector';
import { useFlowStore } from '../../store/flowStore';

export const LiveTrafficStream: React.FC = () => {
  const selectedFlowId = useFlowStore((s) => s.selectedFlowId);

  return (
    <div className="flex-1 flex flex-col md:flex-row h-full overflow-hidden">
      {/* Left / Main: Intercepted Flows Table */}
      <div className={`flex-1 flex flex-col h-full min-w-0 transition-all ${
        selectedFlowId ? 'md:w-1/2 lg:w-7/12' : 'w-full'
      }`}>
        <TrafficTable />
      </div>

      {/* Right: Flow Detail Inspector */}
      {selectedFlowId && (
        <div className="h-72 md:h-full md:w-1/2 lg:w-5/12 border-t md:border-t-0 md:border-l border-border flex flex-col overflow-hidden shadow-2xl">
          <SplitInspector />
        </div>
      )}
    </div>
  );
};
