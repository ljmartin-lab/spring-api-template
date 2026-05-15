-- ============================================================
-- V2: Create password_reset_tokens table
-- ============================================================
-- Short-lived signed tokens for the password reset flow.
-- One active token per user at a time (enforced via unique
-- constraint on user_id where used_at IS NULL).
-- Tokens expire after a configurable TTL (default: 1 hour).
-- ============================================================

CREATE TABLE password_reset_tokens
(
    id         UUID                     NOT NULL DEFAULT gen_random_uuid(),
    user_id    UUID                     NOT NULL,
    token_hash VARCHAR(255)             NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at    TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT pk_password_reset_tokens PRIMARY KEY (id),
    CONSTRAINT uq_password_reset_token_hash UNIQUE (token_hash),
    CONSTRAINT fk_password_reset_tokens_user
        FOREIGN KEY (user_id)
            REFERENCES users (id)
            ON DELETE CASCADE
);

-- Lookup by token hash (used on reset confirmation)
CREATE INDEX idx_prt_token_hash ON password_reset_tokens (token_hash);

-- Lookup all tokens for a user (used to invalidate old tokens on new request)
CREATE INDEX idx_prt_user_id ON password_reset_tokens (user_id);

-- Partial index: enforce only one active (unused, unexpired) token per user
CREATE UNIQUE INDEX uq_prt_one_active_per_user
    ON password_reset_tokens (user_id)
    WHERE used_at IS NULL;