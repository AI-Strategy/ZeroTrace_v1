-- ZeroTrace v1.0.5 - Sovereign Auth Schema
-- Postgres Schema for Passkeys (WebAuthn), Users, and Immutable Audit Logs.

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Users Table (The Identity Root)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    pub_key_id VARCHAR(255), -- Primary Passkey ID
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP WITH TIME ZONE,
    risk_score FLOAT DEFAULT 0.0, -- V36/V35 Logic Drift Score
    is_admin BOOLEAN DEFAULT FALSE
);

-- 2. Passkeys (WebAuthn Credentials)
-- Stores the public key material and liveness metadata.
CREATE TABLE IF NOT EXISTS passkeys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT UNIQUE NOT NULL, -- The WebAuthn Credential ID
    public_key TEXT NOT NULL,           -- COSE encoded public key
    aaguid UUID,                        -- Authenticator Attestation GUID (Hardware Type)
    sign_count INTEGER DEFAULT 0,       -- Replay protection
    last_used TIMESTAMP WITH TIME ZONE,
    liveness_verified BOOLEAN DEFAULT FALSE, -- V53: Was UV enforced?
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. NHI Tokens (Non-Human Identities)
-- Tracks the active sessions for AI Agents.
CREATE TABLE IF NOT EXISTS nhi_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    token_hash TEXT UNIQUE NOT NULL,
    agent_id VARCHAR(255) NOT NULL,
    org_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL, -- V49: Rotation TTL
    revoked BOOLEAN DEFAULT FALSE,                -- V54: Kill-Switch Status
    revocation_reason TEXT
);

-- 4. Immutable Audit Ledger (V42/V54)
-- Write-Only log of all high-risk actions.
CREATE TABLE IF NOT EXISTS audit_ledger (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    actor_id UUID,          -- User or Agent ID
    actor_type VARCHAR(50), -- 'USER', 'AGENT', 'SYSTEM'
    action VARCHAR(100) NOT NULL,
    vector_id VARCHAR(10),  -- e.g., 'V47', 'V51'
    risk_score FLOAT,
    metadata JSONB,
    occurred_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for Speed
CREATE INDEX i_users_email ON users(email);
CREATE INDEX i_passkeys_user ON passkeys(user_id);
CREATE INDEX i_nhi_expires ON nhi_tokens(expires_at) WHERE revoked = FALSE;
CREATE INDEX i_audit_vector ON audit_ledger(vector_id);

-- V54 Zombie Sweep Function
CREATE OR REPLACE FUNCTION revoke_zombies() RETURNS void AS $$
BEGIN
    UPDATE nhi_tokens
    SET revoked = TRUE, revocation_reason = 'TTL_EXPIRED_V54'
    WHERE expires_at < NOW() AND revoked = FALSE;
END;
$$ LANGUAGE plpgsql;
