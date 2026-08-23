import { 
  FlowRecord, 
  EndpointDossier, 
  MutationCategory, 
  StrategyRecommendation 
} from '../types';

/**
 * Metadata dictionary for all mutation test strategies
 */
export const STRATEGY_DEFINITIONS: Record<
  MutationCategory, 
  { 
    name: string; 
    description: string; 
    baseScore: number;
    baseSeverity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    defaultPayloads: string[];
  }
> = {
  IDOR_SEQUENTIAL: {
    name: 'Sequential IDOR & Resource Probing',
    description: 'Increment and decrement integer IDs or shift resource identifiers to probe for broken object level authorization (BOLA).',
    baseScore: 40,
    baseSeverity: 'HIGH',
    defaultPayloads: ['+1', '-1', '0', '1', '999999', '100000000000000000000'],
  },
  IDOR_ROLE_SWAP: {
    name: 'IDOR Role Swap & Cross-Tenant Access',
    description: 'Swap tenant identifiers, role claims, and user IDs with other known test users or elevated privileges.',
    baseScore: 42,
    baseSeverity: 'CRITICAL',
    defaultPayloads: ['user_b_id', 'admin', '00000000-0000-0000-0000-000000000000', 'tenant_test_2'],
  },
  SPECIAL_CHAR_FUZZ: {
    name: 'Reflection & Special Character Fuzzing',
    description: 'Inject XSS, template injection, SQLi, and escape sequence characters into reflected parameters to test contextual encoding.',
    baseScore: 45,
    baseSeverity: 'HIGH',
    defaultPayloads: ['<script>alert(1)</script>', '\' OR 1=1--', '"><svg/onload=alert(1)>', '${7*7}', '{{7*7}}', '`id`'],
  },
  AUTH_STRIPPING: {
    name: 'Auth Stripping & Header Nullification',
    description: 'Drop Authorization headers, nullify Bearer tokens, or swap valid cookies with empty values to check endpoint authorization enforcement.',
    baseScore: 38,
    baseSeverity: 'HIGH',
    defaultPayloads: ['[DROPPED]', 'Bearer null', 'Bearer undefined', 'Basic Og==', 'eyJhbGciOiJub25lIn0.e30.'],
  },
  MASS_ASSIGNMENT: {
    name: 'Mass Assignment & Hidden Property Injection',
    description: 'Inject privileged JSON attributes (is_admin, role, superuser, status, verified, balance) into request payloads.',
    baseScore: 35,
    baseSeverity: 'HIGH',
    defaultPayloads: ['"is_admin": true', '"role": "admin"', '"permissions": ["*"]', '"credit_balance": 999999', '"verified": true'],
  },
  BOUNDARY_OVERFLOW: {
    name: 'Boundary Overflows & Numeric Stress',
    description: 'Test extreme integer boundaries (MAX_INT, negative values, 0, float representations, exponential notation).',
    baseScore: 32,
    baseSeverity: 'MEDIUM',
    defaultPayloads: ['-1', '0', '2147483647', '9223372036854775807', '1e308', 'NaN', '-0.0000001'],
  },
  TYPE_CONFUSION: {
    name: 'Type Confusion & Dynamic Array/Object Swaps',
    description: 'Swap expected string parameters for arrays, objects, booleans, or null to trigger type errors or logic bypasses.',
    baseScore: 30,
    baseSeverity: 'MEDIUM',
    defaultPayloads: ['[]', '{}', 'true', 'false', 'null', '["admin"]', '{"$ne": null}'],
  },
  SCHEMA_MUTATION: {
    name: 'Schema Mutation & Structure Fuzzing',
    description: 'Inject unexpected nested JSON structures, duplicate keys, truncated payloads, and oversized objects.',
    baseScore: 28,
    baseSeverity: 'MEDIUM',
    defaultPayloads: ['{"__proto__": {"admin": true}}', '{"nested": {"depth": 100}}', '{/* corrupted json */'],
  },
};

/**
 * Score and rank all mutation strategies based on target flow and dossier telemetry.
 */
export function getStrategyRecommendations(
  flow?: FlowRecord | null,
  dossier?: EndpointDossier | null
): StrategyRecommendation[] {
  const scores: Record<MutationCategory, { score: number; reason: string; params: string[]; severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' }> = {
    IDOR_SEQUENTIAL: { score: STRATEGY_DEFINITIONS.IDOR_SEQUENTIAL.baseScore, reason: 'Standard identifier probe', params: [], severity: 'HIGH' },
    IDOR_ROLE_SWAP: { score: STRATEGY_DEFINITIONS.IDOR_ROLE_SWAP.baseScore, reason: 'Standard role separation probe', params: [], severity: 'CRITICAL' },
    SPECIAL_CHAR_FUZZ: { score: STRATEGY_DEFINITIONS.SPECIAL_CHAR_FUZZ.baseScore, reason: 'Standard input sanitization probe', params: [], severity: 'HIGH' },
    AUTH_STRIPPING: { score: STRATEGY_DEFINITIONS.AUTH_STRIPPING.baseScore, reason: 'Standard authentication enforcement probe', params: [], severity: 'HIGH' },
    MASS_ASSIGNMENT: { score: STRATEGY_DEFINITIONS.MASS_ASSIGNMENT.baseScore, reason: 'Standard model attribute probe', params: [], severity: 'HIGH' },
    BOUNDARY_OVERFLOW: { score: STRATEGY_DEFINITIONS.BOUNDARY_OVERFLOW.baseScore, reason: 'Standard boundary stress probe', params: [], severity: 'MEDIUM' },
    TYPE_CONFUSION: { score: STRATEGY_DEFINITIONS.TYPE_CONFUSION.baseScore, reason: 'Standard type juggling probe', params: [], severity: 'MEDIUM' },
    SCHEMA_MUTATION: { score: STRATEGY_DEFINITIONS.SCHEMA_MUTATION.baseScore, reason: 'Standard schema structure probe', params: [], severity: 'MEDIUM' },
  };

  if (!flow && !dossier) {
    return rankAndFormatRecommendations(scores);
  }

  // --- 1. REFLECTION HEURISTICS ---
  const reflections = flow?.triage?.reflections || [];
  if (reflections.length > 0) {
    const reflectedParams = reflections.map(r => r.param_name);
    const contexts = Array.from(new Set(reflections.map(r => r.context))).join(', ');
    scores.SPECIAL_CHAR_FUZZ.score = Math.max(scores.SPECIAL_CHAR_FUZZ.score, 98);
    scores.SPECIAL_CHAR_FUZZ.reason = `Endpoint directly reflects parameter(s) [${reflectedParams.join(', ')}] into ${contexts || 'response body'}. Prime target for XSS/template breakouts.`;
    scores.SPECIAL_CHAR_FUZZ.params = reflectedParams;
    scores.SPECIAL_CHAR_FUZZ.severity = 'CRITICAL';
  }

  // --- 2. IDENTIFIER & IDOR HEURISTICS ---
  const identifiers = flow?.triage?.identifiers || [];
  const seqIds = identifiers.filter(i => i.id_type === 'SEQUENTIAL_INT' || i.idor_risk === 'HIGH');
  const pathHasId = flow?.path && /\/(?:users?|orders?|items?|accounts?|docs?|files?|profiles?)\/(\d+|[0-9a-fA-F-]{8,})/i.test(flow.path);
  
  if (seqIds.length > 0) {
    const paramNames = seqIds.map(i => `${i.param_name} (${i.value})`);
    scores.IDOR_SEQUENTIAL.score = Math.max(scores.IDOR_SEQUENTIAL.score, 96);
    scores.IDOR_SEQUENTIAL.reason = `Sequential/predictable identifier(s) [${paramNames.join(', ')}] detected. High risk of BOLA/IDOR object exposure.`;
    scores.IDOR_SEQUENTIAL.params = seqIds.map(i => i.param_name);
    scores.IDOR_SEQUENTIAL.severity = 'CRITICAL';

    scores.IDOR_ROLE_SWAP.score = Math.max(scores.IDOR_ROLE_SWAP.score, 91);
    scores.IDOR_ROLE_SWAP.reason = `Predictable resource identifier detected with active session. Test cross-tenant access control.`;
  } else if (pathHasId) {
    scores.IDOR_SEQUENTIAL.score = Math.max(scores.IDOR_SEQUENTIAL.score, 88);
    scores.IDOR_SEQUENTIAL.reason = `RESTful resource path identifier detected in URL (${flow?.path}). Test for sibling entity access.`;
    scores.IDOR_ROLE_SWAP.score = Math.max(scores.IDOR_ROLE_SWAP.score, 84);
  }

  // --- 3. AUTH & SESSION HEURISTICS ---
  const authPresent = flow?.triage?.auth?.auth_present || 
    Boolean(flow?.request_headers && (flow.request_headers['authorization'] || flow.request_headers['Authorization'] || flow.request_headers['cookie']));
  const authAnomalies = flow?.triage?.auth?.anomaly_flags || [];

  if (authPresent) {
    scores.AUTH_STRIPPING.score = Math.max(scores.AUTH_STRIPPING.score, 89);
    scores.AUTH_STRIPPING.reason = `Active credentials/Bearer token observed. Test endpoint security when authorization tokens are stripped or corrupted.`;
    
    if (authAnomalies.length > 0) {
      scores.AUTH_STRIPPING.score = Math.max(scores.AUTH_STRIPPING.score, 97);
      scores.AUTH_STRIPPING.reason = `Auth state deviation detected (${authAnomalies.join(', ')}). High risk of unauthenticated bypass.`;
      scores.AUTH_STRIPPING.severity = 'CRITICAL';
    }

    scores.IDOR_ROLE_SWAP.score = Math.max(scores.IDOR_ROLE_SWAP.score, 86);
  }

  // --- 4. JSON BODY & MASS ASSIGNMENT HEURISTICS ---
  const isPostOrPutOrPatch = ['POST', 'PUT', 'PATCH'].includes(flow?.method || '');
  const hasJsonBody = Boolean(flow?.request_body && flow.request_body.trim().startsWith('{'));
  const isMutationEndpoint = flow?.triage?.endpoint_category === 'MUTATION_ACTION' || isPostOrPutOrPatch;

  if (hasJsonBody && isMutationEndpoint) {
    scores.MASS_ASSIGNMENT.score = Math.max(scores.MASS_ASSIGNMENT.score, 87);
    scores.MASS_ASSIGNMENT.reason = `Mutation endpoint accepts JSON object payload. Fuzz for unauthorized model attribute tampering (e.g. role, isAdmin).`;
    scores.MASS_ASSIGNMENT.severity = 'HIGH';

    scores.SCHEMA_MUTATION.score = Math.max(scores.SCHEMA_MUTATION.score, 82);
    scores.SCHEMA_MUTATION.reason = `Structured JSON payload detected. Test parser handling with malformed, prototype-polluting, or deep nested keys.`;
  }

  // --- 5. NUMERIC & TYPE BOUNDARIES ---
  const queryParams = flow?.query_params || {};
  const numericParams: string[] = [];
  Object.entries(queryParams).forEach(([k, v]) => {
    if (typeof v === 'string' && /^-?\d+(?:\.\d+)?$/.test(v.trim())) {
      numericParams.push(k);
    }
  });

  if (numericParams.length > 0) {
    scores.BOUNDARY_OVERFLOW.score = Math.max(scores.BOUNDARY_OVERFLOW.score, 80);
    scores.BOUNDARY_OVERFLOW.reason = `Numeric parameters [${numericParams.join(', ')}] detected. Test integer limits, negative values, and zero edge cases.`;
    scores.BOUNDARY_OVERFLOW.params = numericParams;

    scores.TYPE_CONFUSION.score = Math.max(scores.TYPE_CONFUSION.score, 78);
    scores.TYPE_CONFUSION.reason = `Dynamic typed query parameters present. Swap numeric values with string/array types.`;
  }

  // --- 6. DOSSIER PARAMETER CATALOG ENRICHMENT ---
  if (dossier?.parameters) {
    dossier.parameters.forEach((param) => {
      if (param.reflections_count > 0) {
        scores.SPECIAL_CHAR_FUZZ.score = Math.max(scores.SPECIAL_CHAR_FUZZ.score, 95);
        if (!scores.SPECIAL_CHAR_FUZZ.params.includes(param.name)) {
          scores.SPECIAL_CHAR_FUZZ.params.push(param.name);
        }
      }
      if (param.idor_risk === 'HIGH' || param.id_type === 'SEQUENTIAL_INT') {
        scores.IDOR_SEQUENTIAL.score = Math.max(scores.IDOR_SEQUENTIAL.score, 94);
        if (!scores.IDOR_SEQUENTIAL.params.includes(param.name)) {
          scores.IDOR_SEQUENTIAL.params.push(param.name);
        }
      }
      if (param.inferred_type === 'integer' || param.inferred_type === 'float') {
        scores.BOUNDARY_OVERFLOW.score = Math.max(scores.BOUNDARY_OVERFLOW.score, 75);
      }
    });
  }

  return rankAndFormatRecommendations(scores);
}

/**
 * Format score map into sorted and ranked StrategyRecommendation array.
 */
function rankAndFormatRecommendations(
  scores: Record<MutationCategory, { score: number; reason: string; params: string[]; severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' }>
): StrategyRecommendation[] {
  const categories = Object.keys(STRATEGY_DEFINITIONS) as MutationCategory[];
  
  const mapped = categories.map((cat) => {
    const def = STRATEGY_DEFINITIONS[cat];
    const item = scores[cat];
    return {
      category: cat,
      name: def.name,
      description: def.description,
      score: item.score,
      rank: 0,
      isRecommended: false,
      matchReason: item.reason,
      targetParams: item.params,
      suggestedPayloads: def.defaultPayloads,
      severityLikelihood: item.severity,
    };
  });

  // Sort descending by score
  mapped.sort((a, b) => b.score - a.score);

  // Assign 1-indexed ranks and recommendations
  return mapped.map((rec, index) => {
    const rank = index + 1;
    const isRecommended = rank === 1 || rec.score >= 85;
    return {
      ...rec,
      rank,
      isRecommended,
    };
  });
}

/**
 * Get display label for rank badge (e.g. "#1 (Recommended)", "#2", etc.)
 */
export function formatRankLabel(rank: number, isRecommended: boolean): string {
  if (rank === 1) return '#1 (Recommended)';
  if (isRecommended) return `#${rank} (High Fit)`;
  return `#${rank}`;
}

/**
 * Get top recommended strategy
 */
export function getTopRecommendedStrategy(recommendations: StrategyRecommendation[]): StrategyRecommendation {
  return recommendations[0] || {
    category: 'IDOR_SEQUENTIAL',
    name: STRATEGY_DEFINITIONS.IDOR_SEQUENTIAL.name,
    description: STRATEGY_DEFINITIONS.IDOR_SEQUENTIAL.description,
    score: 50,
    rank: 1,
    isRecommended: true,
    matchReason: 'Default baseline strategy',
    suggestedPayloads: STRATEGY_DEFINITIONS.IDOR_SEQUENTIAL.defaultPayloads,
    severityLikelihood: 'HIGH',
  };
}
