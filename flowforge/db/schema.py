"""
SQLite database schema, table definitions, B-tree indexes, and FTS5 triggers.
"""

SCHEMA_SQL = """
-- 1. Core HTTP/HTTPS & WebSocket Flows Table
CREATE TABLE IF NOT EXISTS flows (
    id TEXT PRIMARY KEY,                       -- UUID v4
    timestamp_start REAL NOT NULL,             -- Unix epoch seconds with ms precision
    timestamp_end REAL,                        -- Completion timestamp
    duration_ms REAL,                          -- Roundtrip duration in milliseconds
    
    -- Network & Protocol
    client_ip TEXT,
    client_port INTEGER,
    server_host TEXT NOT NULL,
    server_port INTEGER NOT NULL DEFAULT 80,
    scheme TEXT NOT NULL DEFAULT 'http',       -- 'http', 'https', 'ws', 'wss'
    http_version TEXT NOT NULL DEFAULT 'HTTP/1.1',
    
    -- Request Information
    method TEXT NOT NULL,                      -- 'GET', 'POST', 'PUT', etc.
    url TEXT NOT NULL,                         -- Full absolute URL
    path TEXT NOT NULL,                        -- URL path component
    query_string TEXT DEFAULT '',              -- Raw query string
    query_params TEXT DEFAULT '{}',            -- JSON object/array of parsed query params
    request_headers TEXT NOT NULL DEFAULT '{}',-- JSON key-value array of headers
    request_content_type TEXT,                 -- MIME type
    request_content_length INTEGER DEFAULT 0,
    request_body TEXT,                         -- Text content or base64 if binary
    request_body_is_binary INTEGER DEFAULT 0,  -- Boolean (0=text, 1=binary)
    request_cookies TEXT DEFAULT '{}',         -- JSON parsed cookies
    
    -- Response Information
    response_status_code INTEGER,              -- HTTP status code (200, 404, etc.)
    response_reason TEXT,                      -- Reason phrase (OK, Not Found)
    response_headers TEXT DEFAULT '{}',        -- JSON key-value array of headers
    response_content_type TEXT,                -- MIME type
    response_content_length INTEGER DEFAULT 0,
    response_body TEXT,                        -- Text content or base64 if binary
    response_body_is_binary INTEGER DEFAULT 0, -- Boolean (0=text, 1=binary)
    response_cookies TEXT DEFAULT '{}',        -- JSON parsed cookies
    
    -- Error & WebSocket Tracking
    error_message TEXT,                        -- Connection error/timeout/SSL failure details
    is_websocket INTEGER DEFAULT 0,            -- Boolean flag
    websocket_message_count INTEGER DEFAULT 0, -- Total WS frames captured
    
    -- Security & Triage Metadata
    tags TEXT DEFAULT '[]',                    -- JSON array: ["auth", "mutation", "reflection", "idor_candidate"]
    triage_data TEXT DEFAULT '{}',             -- JSON structured triage analysis output
    
    -- Operator Flags
    is_intercepted INTEGER DEFAULT 0,          -- Was modified by operator
    is_favorite INTEGER DEFAULT 0,             -- Bookmarked in UI
    notes TEXT,                                -- Operator notes
    
    -- Rich Telemetry
    telemetry TEXT DEFAULT '{}'                -- JSON serialized FlowTelemetry
);

-- 2. Performance B-Tree Indices
CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON flows(timestamp_start DESC);
CREATE INDEX IF NOT EXISTS idx_flows_host_path ON flows(server_host, path);
CREATE INDEX IF NOT EXISTS idx_flows_method ON flows(method);
CREATE INDEX IF NOT EXISTS idx_flows_status ON flows(response_status_code);
CREATE INDEX IF NOT EXISTS idx_flows_scheme ON flows(scheme);
CREATE INDEX IF NOT EXISTS idx_flows_is_ws ON flows(is_websocket);
CREATE INDEX IF NOT EXISTS idx_flows_favorite ON flows(is_favorite);

-- 3. WebSocket Messages Table
CREATE TABLE IF NOT EXISTS websocket_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id TEXT NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
    timestamp REAL NOT NULL,
    from_client INTEGER NOT NULL,              -- 1 = client->server, 0 = server->client
    opcode INTEGER NOT NULL DEFAULT 1,         -- 1=Text, 2=Binary, 8=Close, 9=Ping, 10=Pong
    content_length INTEGER NOT NULL DEFAULT 0,
    content TEXT NOT NULL,                     -- UTF-8 text or Base64 binary
    is_binary INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ws_flow_time ON websocket_messages(flow_id, timestamp ASC);

-- 4. Extracted Parameters Table
CREATE TABLE IF NOT EXISTS parameters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id TEXT NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
    endpoint_hash TEXT NOT NULL,               -- Hash of (METHOD + host + path_pattern)
    location TEXT NOT NULL,                    -- 'query', 'header', 'json_body', 'form_body', 'cookie', 'path_param'
    name TEXT NOT NULL,
    value TEXT,
    data_type TEXT DEFAULT 'string',           -- 'string', 'integer', 'float', 'boolean', 'uuid', 'jwt', 'array', 'object'
    is_entropy_token INTEGER DEFAULT 0,
    is_identifier INTEGER DEFAULT 0,
    timestamp REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_params_endpoint ON parameters(endpoint_hash, name);
CREATE INDEX IF NOT EXISTS idx_params_name ON parameters(name);

-- 5. Discovered Endpoints Catalog
CREATE TABLE IF NOT EXISTS endpoints (
    endpoint_hash TEXT PRIMARY KEY,            -- SHA256(method + ':' + host + ':' + path_pattern)
    method TEXT NOT NULL,
    host TEXT NOT NULL,
    path_pattern TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    request_count INTEGER DEFAULT 1,
    category TEXT DEFAULT 'DATA_READ',         -- 'Auth', 'Data Read', 'Mutation/Action', 'Admin'
    schema_summary TEXT DEFAULT '{}'           -- Aggregated inferred schema
);

-- 6. FTS5 Virtual Table for Full-Text Search
CREATE VIRTUAL TABLE IF NOT EXISTS flows_fts USING fts5(
    url,
    request_headers,
    request_body,
    response_headers,
    response_body,
    content='flows',
    content_rowid='rowid',
    tokenize='unicode61 remove_diacritics 2'
);

-- 7. FTS5 Synchronization Triggers
CREATE TRIGGER IF NOT EXISTS flows_fts_ai AFTER INSERT ON flows BEGIN
  INSERT INTO flows_fts(rowid, url, request_headers, request_body, response_headers, response_body)
  VALUES (new.rowid, new.url, new.request_headers, new.request_body, new.response_headers, new.response_body);
END;

CREATE TRIGGER IF NOT EXISTS flows_fts_ad AFTER DELETE ON flows BEGIN
  INSERT INTO flows_fts(flows_fts, rowid, url, request_headers, request_body, response_headers, response_body)
  VALUES('delete', old.rowid, old.url, old.request_headers, old.request_body, old.response_headers, old.response_body);
END;

CREATE TRIGGER IF NOT EXISTS flows_fts_au AFTER UPDATE ON flows BEGIN
  INSERT INTO flows_fts(flows_fts, rowid, url, request_headers, request_body, response_headers, response_body)
  VALUES('delete', old.rowid, old.url, old.request_headers, old.request_body, old.response_headers, old.response_body);
  INSERT INTO flows_fts(rowid, url, request_headers, request_body, response_headers, response_body)
  VALUES (new.rowid, new.url, new.request_headers, new.request_body, new.response_headers, new.response_body);
END;

-- 8. Automated Test Proposals Table
CREATE TABLE IF NOT EXISTS proposals (
    id TEXT PRIMARY KEY,                       -- 'prop-<uuid12>'
    flow_id TEXT NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
    endpoint_hash TEXT,
    endpoint_path TEXT NOT NULL,
    method TEXT NOT NULL,                      -- 'GET', 'POST', etc.
    anomaly_type TEXT NOT NULL,                -- 'REFLECTION', 'IDOR_SEQUENTIAL', etc.
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'MEDIUM',   -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
    confidence_score REAL NOT NULL DEFAULT 70.0,
    
    target_param_name TEXT NOT NULL DEFAULT '',
    target_param_location TEXT NOT NULL DEFAULT 'query',
    baseline_value TEXT,                       -- JSON serialized or string
    mutated_value TEXT,                        -- JSON serialized or string
    auth_override TEXT,                        -- 'DROP', 'USER_B', etc.
    
    state TEXT NOT NULL DEFAULT 'PENDING',     -- 'PENDING', 'APPROVED', 'EXECUTING', 'COMPLETED', 'DISMISSED'
    tags TEXT DEFAULT '[]',                    -- JSON array of tags
    execution_result TEXT DEFAULT '{}',        -- JSON serialized ProposalExecutionResult
    executed_flow_id TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

-- Performance Indexes for Proposals
CREATE INDEX IF NOT EXISTS idx_proposals_flow_id ON proposals(flow_id);
CREATE INDEX IF NOT EXISTS idx_proposals_state ON proposals(state);
CREATE INDEX IF NOT EXISTS idx_proposals_anomaly_type ON proposals(anomaly_type);
CREATE INDEX IF NOT EXISTS idx_proposals_severity ON proposals(severity);
CREATE INDEX IF NOT EXISTS idx_proposals_created ON proposals(created_at DESC);
"""

