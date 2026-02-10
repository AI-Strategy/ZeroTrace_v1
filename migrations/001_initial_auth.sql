-- Sovereign Identity Storage
CREATE TABLE organizations (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE users (
    id UUID PRIMARY KEY,
    org_id UUID REFERENCES organizations(id),
    email TEXT UNIQUE NOT NULL,
    username TEXT NOT NULL
);

-- Passkey Credential Storage
CREATE TABLE credentials (
    id BYTEA PRIMARY KEY, -- The Credential ID
    user_id UUID REFERENCES users(id),
    public_key BYTEA NOT NULL,
    counter BIGINT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
