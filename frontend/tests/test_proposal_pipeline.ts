import { useFlowStore } from '../src/store/flowStore';
import { TestProposal, FlowRecord } from '../src/types';

function assert(condition: boolean, msg: string) {
  if (!condition) {
    console.error(`❌ ASSERTION FAILED: ${msg}`);
    throw new Error(msg);
  }
}

console.log('--- TEST 1: Proposal Store Initialization & Add ---');
const store = useFlowStore.getState();
assert(store.proposals !== undefined, 'Proposals map should be defined');
assert(Array.isArray(store.proposalOrder), 'ProposalOrder should be an array');
assert(store.isApprovalDrawerOpen === false, 'Approval drawer should be closed initially');
assert(store.filterOnlyWithProposals === false, 'Filter only proposals should be false initially');

const sampleProposal1: TestProposal = {
  id: 'prop-test-001',
  flow_id: 'flow-user-profile-101',
  endpoint_path: '/api/v1/users/1001/profile',
  method: 'GET',
  host: 'api.target.internal',
  url: 'https://api.target.internal/api/v1/users/1001/profile',
  target_param_name: 'user_id',
  target_param_location: 'path',
  inferred_vuln_category: 'IDOR / BOLA Privilege Escalation',
  anomaly_type: 'IDOR_SEQUENTIAL',
  severity: 'HIGH',
  risk_rationale: 'Sequential numeric path identifier user_id=1001 detected with profile data exposure',
  baseline_value: 1001,
  mutated_value: 1002,
  status: 'PENDING',
  created_at: new Date().toISOString(),
};

const sampleProposal2: TestProposal = {
  id: 'prop-test-002',
  flow_id: 'flow-search-query-202',
  endpoint_path: '/api/v1/search',
  method: 'GET',
  host: 'api.target.internal',
  url: 'https://api.target.internal/api/v1/search?q=test',
  target_param_name: 'q',
  target_param_location: 'query',
  inferred_vuln_category: 'Input Reflection in HTML Context',
  anomaly_type: 'REFLECTION',
  severity: 'MEDIUM',
  risk_rationale: 'Query parameter q reflected verbatim in response without sanitization',
  baseline_value: 'test',
  mutated_value: '<img src=x onerror=alert(1)>',
  status: 'PENDING',
  created_at: new Date().toISOString(),
};

store.addProposal(sampleProposal1);
store.addProposal(sampleProposal2);

const updatedStore = useFlowStore.getState();
assert(updatedStore.proposals['prop-test-001'] !== undefined, 'Proposal 1 should exist');
assert(updatedStore.proposals['prop-test-002'] !== undefined, 'Proposal 2 should exist');
assert(updatedStore.proposalOrder.includes('prop-test-001'), 'Proposal 1 in order');
assert(updatedStore.proposalOrder.includes('prop-test-002'), 'Proposal 2 in order');
console.log('✅ Test 1 Passed: Proposals successfully added to store');

console.log('--- TEST 2: Flow Proposal Count & Dynamic Highlighting ---');
const flow1Proposals = Object.values(useFlowStore.getState().proposals).filter(
  (p) => p.flow_id === 'flow-user-profile-101' && p.status === 'PENDING'
);
assert(flow1Proposals.length === 1, 'Flow 1 should have exactly 1 staged proposal');
assert(flow1Proposals[0].target_param_name === 'user_id', 'Param should be user_id');
console.log('✅ Test 2 Passed: Dynamic highlighting count matches staged proposals');

console.log('--- TEST 3: Drawer Toggles & Flow Isolation ---');
useFlowStore.getState().toggleApprovalDrawer(true, 'flow-user-profile-101');
assert(useFlowStore.getState().isApprovalDrawerOpen === true, 'Drawer should be open');
assert(useFlowStore.getState().activeProposalFlowId === 'flow-user-profile-101', 'Flow filter should be set');

useFlowStore.getState().toggleApprovalDrawer(false);
assert(useFlowStore.getState().isApprovalDrawerOpen === false, 'Drawer should be closed');
console.log('✅ Test 3 Passed: Drawer toggle and flow isolation verified');

console.log('--- TEST 4: Transfer Proposal to Matrix Builder ---');
useFlowStore.getState().transferProposalToMatrix('prop-test-001');
const matrixStore = useFlowStore.getState();
assert(matrixStore.activeView === 'matrix', 'Active view should switch to matrix');
assert(matrixStore.activeMatrixJob !== null, 'Active matrix job should exist');
assert(matrixStore.activeMatrixJob?.cases.length! > 0, 'Matrix job should have imported cases');
const importedCase = matrixStore.activeMatrixJob?.cases[0];
assert(importedCase?.target_param_name === 'user_id', 'Imported case parameter matches');
assert(importedCase?.mutated_value === 1002, 'Imported mutated value matches');
console.log('✅ Test 4 Passed: Transfer proposal to matrix builder verified');

console.log('--- TEST 5: Save Proposal to Curated Collections ---');
useFlowStore.getState().saveProposalToCurated('prop-test-002', 'group-bola');
const curationStore = useFlowStore.getState();
const bolaGroup = curationStore.payloadGroups['group-bola'];
assert(bolaGroup !== undefined, 'BOLA payload group should exist');
assert(bolaGroup.case_ids.includes('curated-prop-test-002'), 'Curated case ID should be in group');
console.log('✅ Test 5 Passed: Save proposal to curated collections verified');

console.log('--- TEST 6: Proposal Update, Execution, and Diff Summary ---');
useFlowStore.getState().updateProposal('prop-test-001', {
  status: 'EXECUTED',
  state: 'EXECUTED',
  diff_summary: {
    status_code: 200,
    length_delta: 184,
    latency_ms: 32,
    reflected: false,
    anomaly_flag: 'CRITICAL_IDOR',
    verdict_level: 'CRITICAL_IDOR',
    verdict_description: 'IDOR verified: user 1002 profile returned 200 OK with distinct PII',
  },
  execution_result: {
    status_code: 200,
    status_match: true,
    status_delta: '200 == 200',
    length_delta_bytes: 184,
    latency_delta_ms: 32,
    verdict_level: 'CRITICAL_IDOR',
    verdict_description: 'IDOR verified: user 1002 profile returned 200 OK with distinct PII',
  },
});

const executedProposal = useFlowStore.getState().proposals['prop-test-001'];
assert(executedProposal.status === 'EXECUTED', 'Proposal status should be EXECUTED');
assert(executedProposal.diff_summary?.verdict_level === 'CRITICAL_IDOR', 'Verdict level matches');
assert(executedProposal.diff_summary?.length_delta === 184, 'Length delta matches');
console.log('✅ Test 6 Passed: Proposal execution delta updates verified');

console.log('--- TEST 7: Dismissal Lifecycle ---');
useFlowStore.getState().dismissProposal('prop-test-002');
assert(useFlowStore.getState().proposals['prop-test-002'].status === 'DISMISSED', 'Proposal 2 should be DISMISSED');

useFlowStore.getState().dismissAllProposals();
const allProposals = Object.values(useFlowStore.getState().proposals);
const pendingRemaining = allProposals.filter((p) => p.status === 'PENDING');
assert(pendingRemaining.length === 0, 'Zero pending proposals should remain after dismiss all');
console.log('✅ Test 7 Passed: Dismissal lifecycle verified');

console.log('\n========================================================');
console.log('🎉 ALL PROPOSAL PIPELINE FRONTEND UNIT TESTS PASSED!');
console.log('========================================================');
