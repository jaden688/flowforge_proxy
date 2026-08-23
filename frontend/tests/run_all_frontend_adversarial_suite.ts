import { execSync } from 'child_process';

const suites = [
  { name: 'ApiFlowGraph Layout Calculations & Topology', path: 'frontend/tests/test_apiflowgraph_layouts.ts' },
  { name: 'SelectivePruner Extreme Regex & Filters', path: 'frontend/tests/test_selective_pruner_filters.ts' },
  { name: 'Strategy Recommendations Scoring & Ranking', path: 'frontend/tests/test_recommendations_scoring.ts' },
  { name: 'Hex Dump & Multi-View Inspector Stress', path: 'frontend/tests/test_hex_dump_multiview.ts' },
  { name: 'Auto-Find Proposal Pipeline & Operator Approval Workflow', path: 'frontend/tests/test_proposal_pipeline.ts' },
];

console.log("================================================================================");
console.log("FLOWFORGE PROXY - FRONTEND & INTEGRATION ADVERSARIAL CHALLENGER TEST SUITE");
console.log("================================================================================\n");

let totalPassed = 0;
let totalFailed = 0;
const results: { name: string; duration: number; status: 'PASSED' | 'FAILED' }[] = [];

for (const suite of suites) {
  console.log(`>>> Running Suite: ${suite.name} (${suite.path})`);
  const start = performance.now();
  try {
    const output = execSync(`npx --yes tsx ${suite.path}`, { stdio: 'inherit' });
    const duration = performance.now() - start;
    totalPassed++;
    results.push({ name: suite.name, duration, status: 'PASSED' });
    console.log(`[PASS] ${suite.name} completed in ${(duration / 1000).toFixed(2)}s\n`);
  } catch (err: any) {
    const duration = performance.now() - start;
    totalFailed++;
    results.push({ name: suite.name, duration, status: 'FAILED' });
    console.error(`[FAIL] ${suite.name} failed after ${(duration / 1000).toFixed(2)}s\n`);
  }
}

console.log("================================================================================");
console.log("ADVERSARIAL CHALLENGE EXECUTION SUMMARY");
console.log("================================================================================");
results.forEach((r) => {
  console.log(`- [${r.status}] ${r.name} (${(r.duration / 1000).toFixed(2)}s)`);
});
console.log(`\nTotal Suites: ${suites.length} | Passed: ${totalPassed} | Failed: ${totalFailed}`);

if (totalFailed > 0) {
  console.error("\n❌ CHALLENGE FAILED: Some adversarial tests failed.");
  process.exit(1);
} else {
  console.log("\n✅ ALL FRONTEND ADVERSARIAL CHALLENGE TESTS PASSED EMPIRICALLY!");
  process.exit(0);
}
