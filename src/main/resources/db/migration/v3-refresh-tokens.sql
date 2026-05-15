-- ============================================================
-- V3: Create refresh_tokens table
-- ============================================================
-- Persisted refresh tokens for the JWT auth flow.
-- Access tokens are short-lived (15 min) and stateless.
-- Refresh tokens are long-lived (7 days), stored here, and
-- rotated on every use (old token revoked, new one issued).
-- Multiple active sessions per user are supported (one row
-- per device/session).
-- ============================================================

CREATE TABLE refresh_tokens
(
    id          UUID                     NOT NULL DEFAULT gen_random_uuid(),
    user_id     UUID                     NOT NULL,
    token_hash  VARCHAR(255)             NOT NULL,
    device_info VARCHAR(255),
    ip_address  VARCHAR(45),
    expires_at  TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at  TIMESTAMP WITH TIME ZONE,
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT pk_refresh_tokens PRIMARY KEY (id),
    CONSTRAINT uq_refresh_token_hash UNIQUE (token_hash),
    CONSTRAINT fk_refresh_tokens_user
        FOREIGN KEY (user_id)
            REFERENCES users (id)
            ON DELETE CASCADE
);

-- Lookup by token hash on every refresh request
CREATE INDEX idx_rt_token_hash ON refresh_tokens (token_hash);

-- Lookup all active sessions for a user (used for session management / logout-all)
CREATE INDEX idx_rt_user_id ON refresh_tokens (user_id);

-- Partial index for active (non-revoked, non-expired) tokens only
CREATE INDEX idx_rt_active
    ON refresh_tokens (user_id, expires_at)
    WHERE revoked_at IS NULL;