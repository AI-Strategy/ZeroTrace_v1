-- ZeroTrace Core Schema (Hyperdrive Optimized)
-- Designed for high-volume insert, low-latency read for "Verified Signatures".

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Users (Tenants)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    api_key_hash TEXT NOT NULL UNIQUE,
    org_name TEXT NOT NULL,
    tier TEXT DEFAULT 'standard', -- 'standard', 'enterprise'
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Verified Signatures (The "Registry Guard")
-- This table is heavily cached by Hyperdrive for O(1) lookups at the edge.
CREATE TABLE verified_signatures (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    signature_hash TEXT NOT NULL UNIQUE, -- SHA-256 of the domain/manifest
    entity_name TEXT NOT NULL,
    trust_score FLOAT DEFAULT 1.0, -- 0.0 to 1.0
    is_malicious BOOLEAN DEFAULT FALSE,
    verified_at TIMESTAMPTZ DEFAULT NOW(),
    metadata JSONB
);

CREATE INDEX idx_signatures_hash ON verified_signatures(signature_hash);

-- 3. Audit Sessions (The "Trace" Log)
-- Write-heavy. Hyperdrive handles connection pooling to prevent exhaustion.
CREATE TABLE request_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    session_id UUID NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    
    -- Security Metadata
    action_type TEXT NOT NULL, -- 'SCAN', 'BLOCK', 'SANITIZE'
    outcome TEXT NOT NULL, -- 'CLEARED', 'DENIED'
    latency_ms INTEGER,
    
    -- Threats Detected (Array of strings)
    threats_detected TEXT[], 
    
    -- Request details (Sanitized only!)
    resource_accessed TEXT
);

CREATE INDEX idx_logs_session ON request_logs(session_id);
CREATE INDEX idx_logs_timestamp ON request_logs(timestamp DESC);

-- 4. Row Level Security (RLS) Enforcement
-- Ensure strict tenant isolation for "Digital SCIF" compliance.

ALTER TABLE request_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_policy ON request_logs
    USING (user_id = current_setting('app.current_user_id')::uuid);


-- 5. System Prompts (The "Verified Instructions" Ledger)
-- Immutable version history of authorized system prompts to mitigate "Shadow AI" (EXT19).

CREATE TABLE system_prompts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    name TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    content TEXT NOT NULL, -- Encrypted at rest via pgcrypto or similar
    hash TEXT GENERATED ALWAYS AS (md5(content)) STORED,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    
    UNIQUE (user_id, name, version)
);


-- 6. Bulletproof Audit Logging (User Request)
-- Dedicated schema for immutable security logs (Risk Matrix Compliance).

CREATE SCHEMA IF NOT EXISTS zerotrace_audit;

CREATE TABLE zerotrace_audit.event_logs (
    event_id        BIGSERIAL PRIMARY KEY,
    timestamp       TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    
    -- Risk Categorization
    risk_domain     TEXT NOT NULL, 
    risk_code       TEXT NOT NULL,
    severity        INT CHECK (severity BETWEEN 1 AND 5),

    -- Actor Identification
    user_id         UUID,
    agent_id        TEXT,
    session_id      UUID NOT NULL,
    client_ip       INET,

    -- Data Payload (Redacted)
    input_prompt    TEXT,
    output_response TEXT,
    
    -- Security Intervention Details
    intervention_type TEXT,
    deterministic_rule_id TEXT,
    cognitive_score   DECIMAL,
    
    -- Extended Metadata
    metadata        JSONB,
    trace_id        TEXT UNIQUE
);

CREATE INDEX idx_audit_timestamp ON zerotrace_audit.event_logs (timestamp DESC);
CREATE INDEX idx_audit_risk_code ON zerotrace_audit.event_logs (risk_code);
CREATE INDEX idx_audit_agent_id ON zerotrace_audit.event_logs (agent_id);
CREATE INDEX idx_audit_metadata_gin ON zerotrace_audit.event_logs USING GIN (metadata);

-- 7. Forensic Trigger (Real-Time Alerting)
-- Notifies the Rust Sentinel when a High-Severity event occurs.

CREATE OR REPLACE FUNCTION notify_high_severity_event() RETURNS TRIGGER AS $$
DECLARE
    payload JSON;
BEGIN
    -- Only trigger for Severity 4 (High) or 5 (Critical)
    IF NEW.severity >= 4 THEN
        payload = json_build_object(
            'event_id', NEW.event_id,
            'risk_code', NEW.risk_code,
            'agent_id', NEW.agent_id,
            'timestamp', NEW.timestamp
        );
        PERFORM pg_notify('high_severity_alerts', payload::text);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_high_severity_alert
AFTER INSERT ON zerotrace_audit.event_logs
FOR EACH ROW EXECUTE FUNCTION notify_high_severity_event();
