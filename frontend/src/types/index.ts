// ============================================================================
// Core Flow & Traffic Data Models
// ============================================================================

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS' | 'WS';

export type EndpointCategory = 'AUTH' | 'DATA_READ' | 'MUTATION_ACTION' | 'ADMIN' | 'TELEMETRY' | 'UNKNOWN';

export type IdType = 'SEQUENTIAL_INT' | 'UUID_V4' | 'UUID_V1' | 'ULID' | 'MONGO_OBJECTID' | 'HASH' | 'OPAQUE';

export type IdorRiskLevel = 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';

export type ReflectionContext = 'HTML_BODY' | 'HTML_ATTRIBUTE' | 'JS_SCRIPT' | 'JSON_VALUE' | 'RESPONSE_HEADER';

export interface ParamReflection {
  param_name: string;
  source: 'query' | 'path' | 'body' | 'header' | 'cookie';
  value: string;
  match_type: 'exact' | 'url_encoded' | 'html_entity' | 'base64';
  context: ReflectionContext;
  offsets: [number, number][]; // [start, end] positions in response
  xss_indicator: boolean;
}

export interface AuthFinding {
  auth_present: boolean;
  auth_type: 'BEARER_JWT' | 'SESSION_COOKIE' | 'API_KEY' | 'BASIC' | 'NONE';
  token_preview?: string;
  jwt_claims?: Record<string, unknown>;
  anomaly_flags: string[]; // e.g. ['MISSING_ON_ADMIN', 'EXPIRED_ACCEPTED', 'ROLE_ELEVATION']
}

export interface EntropyFinding {
  param_name: string;
  value_preview: string;
  shannon_entropy: number;
  secret_pattern?: 'AWS_KEY' | 'STRIPE_KEY' | 'GITHUB_TOKEN' | 'JWT' | 'GENERIC_HIGH_ENTROPY';
}

export interface IdClassification {
  param_name: string;
  value: string;
  id_type: IdType;
  idor_risk: IdorRiskLevel;
}

export interface TriageSummary {
  endpoint_category: EndpointCategory;
  reflections: ParamReflection[];
  auth: AuthFinding;
  entropy: EntropyFinding[];
  identifiers: IdClassification[];
  has_anomalies: boolean;
}

// ============================================================================
// Telemetry & Network Timing Models
// ============================================================================

export interface CertificateInfo {
  subject?: string;
  issuer?: string;
  valid_from?: string;
  valid_until?: string;
  is_expired?: boolean;
  fingerprint_sha256?: string;
  key_algorithm?: string;
  key_size_bits?: number;
  sans?: string[];
}

export interface TelemetryMetrics {
  // Latency & Waterfall Milestones (in milliseconds)
  dns_ms?: number;
  tcp_connect_ms?: number;
  tls_handshake_ms?: number;
  ttfb_ms?: number; // Time to First Byte
  content_download_ms?: number;
  total_duration_ms?: number;

  // TLS & Protocol Details
  tls_version?: 'TLSv1.3' | 'TLSv1.2' | 'TLSv1.1' | 'TLSv1.0' | 'None' | string;
  cipher_suite?: string;
  sni?: string;
  alpn?: 'h2' | 'http/1.1' | 'h3' | string;
  http_version?: string;
  connection_reused?: boolean;
  server_ip?: string;
  client_ip?: string;

  // Bandwidth & Size
  request_headers_bytes?: number;
  request_body_bytes?: number;
  response_headers_bytes?: number;
  response_body_bytes?: number;
  total_bytes_sent?: number;
  total_bytes_received?: number;
  transfer_speed_kbps?: number;

  // Security & Certificate
  certificate?: CertificateInfo;
}

export interface FlowRecord {
  id: string; // UUID v4
  timestamp: string; // ISO 8601 or epoch string
  client_ip: string;
  method: HttpMethod;
  url: string;
  host: string;
  path: string;
  query_params?: Record<string, string | string[] | any>;
  request_headers?: Record<string, string>;
  request_body?: string | null;
  request_content_type?: string | null;
  request_size?: number;

  // Response (Nullable if flow is currently in-flight)
  response_status?: number | null;
  response_status_code?: number | null;
  response_status_text?: string | null;
  response_reason?: string | null;
  response_headers?: Record<string, string> | null;
  response_body?: string | null;
  response_content_type?: string | null;
  response_size?: number | null;
  latency_ms?: number | null;
  duration_ms?: number | null;

  // Security & Triage Annotations
  tags?: string[];
  triage?: TriageSummary;

  // Rich Telemetry
  telemetry?: TelemetryMetrics;
}

// ============================================================================
// Multi-View Inspector & Renderer Models
// ============================================================================

export type InspectorSubView = 
  | 'formatted' 
  | 'hex' 
  | 'form' 
  | 'raw' 
  | 'headers' 
  | 'telemetry';

export interface FormDataField {
  name: string;
  value: string;
  type: 'text' | 'file' | 'json' | 'binary';
  filename?: string;
  content_type?: string;
  size_bytes?: number;
  is_reflected?: boolean;
}

export interface ParsedFormData {
  is_multipart: boolean;
  boundary?: string;
  fields: FormDataField[];
  raw_count: number;
}

// ============================================================================
// Multi-Layer Decoder Models
// ============================================================================

export type DecoderOperationType =
  | 'base64_decode'
  | 'base64_encode'
  | 'base64url_decode'
  | 'base64url_encode'
  | 'url_decode'
  | 'url_encode'
  | 'hex_decode'
  | 'hex_encode'
  | 'hex_dump'
  | 'html_decode'
  | 'html_encode'
  | 'jwt_decode'
  | 'json_prettify'
  | 'json_minify'
  | 'rot13'
  | 'gzip_decompress';

export type DetectedFormatType =
  | 'JWT'
  | 'BASE64'
  | 'BASE64_URL'
  | 'URL_ENCODED'
  | 'HEX_STREAM'
  | 'HTML_ENTITIES'
  | 'JSON'
  | 'XML'
  | 'PLAIN_TEXT';

export interface FormatDetectionResult {
  format: DetectedFormatType;
  confidence: number; // 0 to 1
  label: string;
  suggestedOperations: DecoderOperationType[];
  preview?: string;
}

export interface JwtSecurityFlag {
  level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  title: string;
  description: string;
}

export interface JwtExpiryStatus {
  is_expired: boolean;
  expires_at?: Date;
  issued_at?: Date;
  not_before?: Date;
  relative_expiry: string; // e.g. "Expired 2 hours ago" or "Expires in 15 mins"
  status_badge: 'EXPIRED' | 'ACTIVE' | 'NOT_YET_VALID' | 'NO_EXPIRY';
}

export interface JwtHeader {
  alg?: string;
  typ?: string;
  kid?: string;
  [key: string]: unknown;
}

export interface JwtPayload {
  sub?: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  roles?: string[] | string;
  role?: string;
  is_admin?: boolean;
  email?: string;
  [key: string]: unknown;
}

export interface JwtDecoded {
  raw: string;
  header_raw: string;
  payload_raw: string;
  signature_raw: string;
  header: JwtHeader;
  payload: JwtPayload;
  signature_valid_format: boolean;
  expiry: JwtExpiryStatus;
  security_flags: JwtSecurityFlag[];
  sensitive_claims: { key: string; value: unknown; label: string }[];
}

export interface DecoderStep {
  id: string;
  operation: DecoderOperationType;
  input: string;
  output: string;
  error?: string;
  duration_ms: number;
  entropy_delta: number;
}

export interface DecoderChainResult {
  initial_input: string;
  final_output: string;
  steps: DecoderStep[];
  success: boolean;
  jwt_data?: JwtDecoded;
}

// ============================================================================
// Target Dossier & Parameter Schema Models
// ============================================================================

export interface ParameterCatalogItem {
  name: string;
  location: 'query' | 'path' | 'body' | 'header' | 'cookie';
  inferred_type: 'string' | 'integer' | 'float' | 'boolean' | 'array' | 'object' | 'null';
  id_type?: IdType;
  idor_risk: IdorRiskLevel;
  required: boolean;
  nullable: boolean;
  sample_values: string[];
  reflections_count: number;
  last_seen: string;
}

export interface EndpointDossier {
  host: string;
  path_template: string; // e.g. "/api/v1/orders/{order_id}"
  methods: HttpMethod[];
  primary_category: EndpointCategory;
  auth_types_observed: string[];
  parameters: ParameterCatalogItem[];
  inferred_json_schema?: Record<string, unknown>;
  total_calls_observed: number;
  sample_flow_ids: string[];
  anomalies_detected: string[];
}

// ============================================================================
// Test Matrix Staging & Execution Models
// ============================================================================

export type MutationCategory = 
  | 'IDOR_SEQUENTIAL'
  | 'IDOR_ROLE_SWAP'
  | 'TYPE_CONFUSION'
  | 'BOUNDARY_OVERFLOW'
  | 'SPECIAL_CHAR_FUZZ'
  | 'AUTH_STRIPPING'
  | 'MASS_ASSIGNMENT'
  | 'SCHEMA_MUTATION';

export type TestExecutionStatus = 'READY' | 'QUEUED' | 'RUNNING' | 'PASSED' | 'ANOMALY_DETECTED' | 'FAILED';

export interface TestMatrixCase {
  id: string;
  name: string;
  endpoint_path: string;
  method: HttpMethod;
  category: MutationCategory;
  target_param_location: 'query' | 'path' | 'body' | 'header';
  target_param_name: string;
  baseline_value: unknown;
  mutated_value: unknown;
  auth_override?: 'DROP' | 'USER_B' | 'EXPIRED' | 'ADMIN';
  selected: boolean;
  status: TestExecutionStatus;
  baseline_flow_id?: string;
  executed_flow_id?: string;
  is_pinned?: boolean;
  is_starred?: boolean;
  group_id?: string;
  notes?: string;
  result_summary?: {
    status_code: number;
    length_delta: number;
    latency_ms: number;
    reflected: boolean;
    anomaly_flag: string | null;
  };
}

export interface TestMatrixJob {
  job_id: string;
  target_endpoint: string;
  created_at: string;
  cases: TestMatrixCase[];
  total_count: number;
  completed_count: number;
  anomalies_count: number;
  is_running: boolean;
}

// ============================================================================
// Request / Response Diff Models
// ============================================================================

export interface DiffSegment {
  type: 'added' | 'removed' | 'unchanged';
  value: string;
  line_number?: number;
}

export interface HeaderDiff {
  key: string;
  val_a?: string;
  val_b?: string;
  status: 'added' | 'removed' | 'modified' | 'identical';
}

export interface AnomalyVerdict {
  level: 'CRITICAL_IDOR' | 'HIGH_REFLECTION' | 'AUTH_BYPASS' | 'INFO_DIFF' | 'IDENTICAL';
  description: string;
}

export interface FlowComparisonResult {
  flow_a: FlowRecord;
  flow_b: FlowRecord;
  status_match: boolean;
  status_delta: string;
  length_delta_bytes: number;
  length_delta_percent: number;
  latency_delta_ms: number;
  header_diffs: HeaderDiff[];
  body_diff_segments: DiffSegment[];
  anomaly_verdict: AnomalyVerdict;
}

// ============================================================================
// UI Navigation & Filter State
// ============================================================================

export type ActiveView = 'cockpit' | 'stream' | 'dossier' | 'matrix' | 'diff' | 'settings' | 'graph' | 'rules';


export interface FilterState {
  search: string;
  methods: HttpMethod[];
  statusGroup: 'all' | '2xx' | '3xx' | '4xx' | '5xx';
  tags: string[];
  host: string;
  onlyAnomalies: boolean;
}

// ============================================================================
// Payload Curation, Collections & Pruning Models
// ============================================================================

export interface CuratedPayloadGroup {
  id: string;
  name: string;
  description?: string;
  color?: string;
  tags?: string[];
  case_ids: string[];
  created_at: string;
  updated_at: string;
}

export interface PruneOptions {
  statuses?: TestExecutionStatus[];
  minLengthDelta?: number;
  maxLengthDelta?: number;
  regexPattern?: string;
  statusCodeFilter?: string; // e.g. "404,500" or empty
  onlyUnselected?: boolean;
  keepPinnedAndStarred: boolean;
}

// ============================================================================
// Strategy Recommendation & Context-Aware Ranking Models
// ============================================================================

export interface StrategyRecommendation {
  category: MutationCategory;
  name: string;
  description: string;
  score: number; // 0 - 100
  rank: number; // 1, 2, 3...
  isRecommended: boolean;
  matchReason: string;
  targetParams?: string[];
  suggestedPayloads?: string[];
  severityLikelihood: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
}

// ============================================================================
// Interactive API Flow Graph & Lineage Models
// ============================================================================

export type LineageEdgeType = 
  | 'AUTH_TOKEN' 
  | 'PARAM_ID' 
  | 'SESSION_COOKIE' 
  | 'STATE_SEQUENCE' 
  | 'GENERIC_DATA';

export interface GraphNodeData {
  id: string;
  label: string;
  host: string;
  path: string;
  method: HttpMethod;
  category: EndpointCategory;
  riskScore: number; // 0 - 100
  anomalies: string[];
  reflectionsCount: number;
  idorRisk: IdorRiskLevel;
  authPresent: boolean;
  dossierKey: string;
  callCount: number;
  lastStatusCode?: number;
  x?: number;
  y?: number;
  selected?: boolean;
}

export interface GraphEdgeData {
  id: string;
  sourceNodeId: string;
  targetNodeId: string;
  lineageType: LineageEdgeType;
  carriedKey: string;
  carriedValueSample?: string;
  confidence?: number;
  active?: boolean;
}

export interface FlowGraphLayout {
  nodes: GraphNodeData[];
  edges: GraphEdgeData[];
}

// ============================================================================
// Custom Heuristics & Match Rule Engine Models (YAML / JSON)
// ============================================================================

export type RuleSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type MatchField = 
  | 'url' 
  | 'path' 
  | 'method' 
  | 'header' 
  | 'query_param' 
  | 'request_body' 
  | 'response_body' 
  | 'status_code' 
  | 'entropy' 
  | 'content_type' 
  | 'latency_ms';

export type MatchOperator = 
  | 'equals' 
  | 'not_equals' 
  | 'contains' 
  | 'not_contains' 
  | 'regex' 
  | 'gt' 
  | 'lt' 
  | 'exists' 
  | 'not_exists' 
  | 'starts_with' 
  | 'ends_with';

export interface MatchCondition {
  id?: string;
  field: MatchField;
  operator: MatchOperator;
  key?: string; // Header or Param key name (e.g. "Authorization", "user_id")
  value: string | number;
  case_sensitive?: boolean;
}

export interface CustomRule {
  id: string;
  name: string;
  description: string;
  severity: RuleSeverity;
  enabled: boolean;
  tags: string[];
  match_logic: 'ALL' | 'ANY';
  conditions: MatchCondition[];
  raw_yaml?: string;
  matches_count: number;
  last_matched_at?: string;
  created_at: string;
  updated_at: string;
}

export interface ConditionEvalResult {
  conditionIndex: number;
  field: MatchField;
  operator: MatchOperator;
  passed: boolean;
  actualValue?: string;
  reason: string;
}

export interface RuleLiveMatchResult {
  ruleId: string;
  ruleName: string;
  severity: RuleSeverity;
  matched: boolean;
  conditionResults: ConditionEvalResult[];
  timestamp: string;
}

// ============================================================================
// Automated Test Proposals & Operator Approval Models (M3 - M4)
// ============================================================================

export type ProposalStatus = 'PENDING' | 'APPROVED' | 'EXECUTING' | 'EXECUTED' | 'DISMISSED' | 'COMPLETED';

export type AnomalyType = 
  | 'REFLECTION' 
  | 'IDOR_SEQUENTIAL' 
  | 'AUTH_DEVIATION' 
  | 'JSON_SCHEMA' 
  | 'JWT_ANOMALY' 
  | 'SECRET_EXPOSURE' 
  | 'CUSTOM_RULE'
  | string;

export interface ProposalDiffSummary {
  status_code: number;
  length_delta: number;
  latency_ms: number;
  reflected: boolean;
  anomaly_flag: string | null;
  status_match?: boolean;
  status_delta?: string;
  verdict_level?: string;
  verdict_description?: string;
}

export interface ProposalExecutionResult {
  executed_at?: number;
  duration_ms?: number;
  status_code?: number;
  status_match?: boolean;
  status_delta?: string;
  length_delta_bytes?: number;
  length_delta_percent?: number;
  latency_delta_ms?: number;
  reflected?: boolean;
  anomaly_detected?: boolean;
  verdict_level?: string; // 'CRITICAL_IDOR' | 'HIGH_REFLECTION' | 'AUTH_BYPASS' | 'INFO_DIFF' | 'IDENTICAL'
  verdict_description?: string;
  executed_flow_id?: string;
  response_headers?: Record<string, string>;
  response_body_preview?: string;
}

export interface TestProposal {
  id: string;                                    // UUID or proposal ID (e.g. prop-xxx)
  flow_id: string;                               // Originating intercepted flow ID
  endpoint_hash?: string;
  endpoint_path: string;                         // e.g. "/api/v1/orders/{id}"
  method: HttpMethod | string;                   // 'GET' | 'POST' | etc.
  host?: string;                                 // e.g. "api.target.com"
  url?: string;                                  // Full URL
  target_param_location: 'query' | 'path' | 'body' | 'header' | 'cookie' | string;
  target_param_name: string;                     // e.g. "order_id"
  anomaly_type?: AnomalyType;
  category?: MutationCategory | string;          // 'IDOR_SEQUENTIAL' | 'TYPE_CONFUSION' | etc.
  inferred_vuln_category: string;                // "IDOR / BOLA Privilege Escalation"
  title?: string;
  description?: string;
  severity: RuleSeverity | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence_score?: number;
  risk_rationale: string;                        // "Sequential numeric parameter 'order_id=1001' detected..."
  baseline_value: unknown;                       // 1001
  mutated_value: unknown;                        // 1002
  auth_override?: 'DROP' | 'USER_B' | 'EXPIRED' | 'ADMIN' | 'ALG_NONE' | string | null;
  payload_preview?: string;                      // Full preview of mutated request body/query
  status: ProposalStatus;                        // 'PENDING' | 'APPROVED' | 'DISMISSED' | 'EXECUTED'
  state?: ProposalStatus;                        // Backend alias for status
  created_at: string | number;                   // ISO 8601 or epoch timestamp
  updated_at?: string | number;
  tags?: string[];
  executed_flow_id?: string;                     // Flow ID produced upon execution
  execution_result?: ProposalExecutionResult;
  diff_summary?: ProposalDiffSummary;
}

export interface ProposalStats {
  total: number;
  pending: number;
  approved: number;
  executing: number;
  completed: number;
  dismissed: number;
}


