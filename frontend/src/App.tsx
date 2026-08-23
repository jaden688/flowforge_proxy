import React, { useEffect } from 'react';
import { useFlowStore } from './store/flowStore';
import { useWebSocket } from './hooks/useWebSocket';
import { api } from './services/api';
import { HeaderNav } from './components/layout/HeaderNav';
import { StatusBar } from './components/layout/StatusBar';
import { LiveTrafficStream } from './components/stream/LiveTrafficStream';
import { TargetDossier } from './components/dossier/TargetDossier';
import { TestMatrixStaging } from './components/matrix/TestMatrixStaging';
import { DiffViewer } from './components/diff/DiffViewer';
import { ApiFlowGraph } from './components/graph/ApiFlowGraph';
import { RuleEngineManager } from './components/rules/RuleEngineManager';
import { ProposalApprovalDrawer } from './components/proposals/ProposalApprovalDrawer';
import { ProposalDiffModal } from './components/proposals/ProposalDiffModal';
import { OperatorCockpit } from './components/cockpit/OperatorCockpit';

export const App: React.FC = () => {
  const activeView = useFlowStore((s) => s.activeView);
  const selectFlow = useFlowStore((s) => s.selectFlow);
  const addFlow = useFlowStore((s) => s.addFlow);
  const setProposals = useFlowStore((s) => s.setProposals);
  const isPaused = useFlowStore((s) => s.isPaused);
  const setPaused = useFlowStore((s) => s.setPaused);

  // Initialize WebSocket connection
  useWebSocket();

  // Load initial flows and staged proposals from backend REST API
  useEffect(() => {
    const fetchInitialData = async () => {
      try {
        const data = await api.getFlows({ limit: 100 });
        if (data && data.flows) {
          data.flows.forEach((flow) => {
            addFlow(flow);
          });
        }
      } catch (e) {
        // Backend may still be initializing
      }

      try {
        const proposalData = await api.getProposals();
        if (proposalData && proposalData.items) {
          setProposals(proposalData.items);
        }
      } catch (e) {
        // Backend proposals route may be initializing
      }
    };
    fetchInitialData();
  }, [addFlow, setProposals]);

  // Global Keyboard Shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Avoid triggering when user is typing in input or textarea
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes((e.target as HTMLElement).tagName)) {
        return;
      }

      if (e.code === 'Space') {
        e.preventDefault();
        setPaused(!isPaused);
      } else if (e.key === 'Escape') {
        selectFlow(null);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isPaused, setPaused, selectFlow]);

  return (
    <div className="h-screen w-screen flex flex-col bg-background text-slate-100 overflow-hidden select-none">
      {/* Top Navigation Bar */}
      <HeaderNav />

      {/* Main Interactive Workbench Viewport */}
      <main className="flex-1 flex flex-col min-h-0 overflow-hidden relative">
        {activeView === 'cockpit' && <OperatorCockpit />}
        {activeView === 'stream' && <LiveTrafficStream />}
        {activeView === 'dossier' && <TargetDossier />}
        {activeView === 'matrix' && <TestMatrixStaging />}
        {activeView === 'diff' && <DiffViewer />}
        {activeView === 'graph' && <ApiFlowGraph />}
        {activeView === 'rules' && <RuleEngineManager />}
      </main>


      {/* Slide-out Operator Approval & Execution Drawer */}
      <ProposalApprovalDrawer />

      {/* Instant Baseline vs Replay Diff Inspector Modal */}
      <ProposalDiffModal />

      {/* Bottom Status Bar */}
      <StatusBar />
    </div>
  );
};

export default App;
