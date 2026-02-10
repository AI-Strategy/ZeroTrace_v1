-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- -----------------------------------------------------------------------------
-- 1. Identity & Access Management (IAM)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- WebAuthn / Passkey Credentials
-- Stores the public key and metadata for FIDO2 authentication.
CREATE TABLE IF NOT EXISTS passkey_credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- The Credential ID (raw bytes from authenticator)
    credential_id BYTEA NOT NULL UNIQUE,
    
    -- The COSE-encoded public key
    public_key BYTEA NOT NULL,
    
    -- Full attestation object (for rigorous audits)
    attestation_object BYTEA NOT NULL,
    
    -- Sign counter for clone detection
    sign_count INT NOT NULL DEFAULT 0,
    
    -- Authenticator Attestation GUID (AAGUID)
    aaguid UUID,
    
    -- User-friendly label (e.g., "YubiKey 5C")
    label TEXT,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

CREATE INDEX idx_passkey_user_id ON passkey_credentials(user_id);
CREATE INDEX idx_passkey_credential_id ON passkey_credentials(credential_id);

-- -----------------------------------------------------------------------------
-- 2. Audit & Compliance
-- -----------------------------------------------------------------------------

CREATE SCHEMA IF NOT EXISTS zerotrace_audit;

-- Immutable Event Log for AI Interactions
CREATE TABLE IF NOT EXISTS zerotrace_audit.event_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Risk Classification
    risk_domain TEXT NOT NULL, -- e.g., "prompt_injection", "pii_leak"
    risk_code TEXT NOT NULL,   -- e.g., "LLM01", "PII-02"
    severity INT NOT NULL,     -- 1 (Low) to 5 (Critical)
    
    -- Context
    user_id UUID,              -- Nullable for anonymous sessions
    agent_id TEXT,             -- The AI Agent involved
    session_id UUID NOT NULL,  -- Correlation ID
    
    -- Payload
    input_prompt TEXT,         -- The user's input (redacted if PII)
    intervention_type TEXT NOT NULL, -- "block", "sanitize", "monitor"
    deterministic_rule_id TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_severity ON zerotrace_audit.event_logs(severity);
CREATE INDEX idx_audit_user_id ON zerotrace_audit.event_logs(user_id);
CREATE INDEX idx_audit_created_at ON zerotrace_audit.event_logs(created_at);
