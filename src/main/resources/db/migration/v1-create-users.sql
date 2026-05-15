-- ============================================================
-- V1: Create users table
-- ============================================================
-- Stores all user accounts. Passwords are always BCrypt hashed
-- and never stored in plain text. Account locking is automatic
-- after exceeding failed login attempts (enforced in service layer).
-- ============================================================

CREATE TABLE users
(
    id                    UUID                     NOT NULL DEFAULT gen_random_uuid(),
    username              VARCHAR(50)              NOT NULL,
    email                 VARCHAR(255)             NOT NULL,
    password_hash         VARCHAR(255)             NOT NULL,
    first_name            VARCHAR(100),
    last_name             VARCHAR(100),
    role                  VARCHAR(50)              NOT NULL DEFAULT 'USER',
    enabled               BOOLEAN                  NOT NULL DEFAULT TRUE,
    account_locked        BOOLEAN                  NOT NULL DEFAULT FALSE,
    failed_login_attempts INTEGER                  NOT NULL DEFAULT 0,
    last_login_at         TIMESTAMP WITH TIME ZONE,
    created_at            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT pk_users PRIMARY KEY (id),
    CONSTRAINT uq_users_username UNIQUE (username),
    CONSTRAINT uq_users_email UNIQUE (email),
    CONSTRAINT chk_users_role CHECK (role IN ('USER', 'ADMIN')),
    CONSTRAINT chk_users_failed_attempts CHECK (failed_login_attempts >= 0)
);

-- Index for login lookup (most frequent query)
CREATE INDEX idx_users_username ON users (username);
CREATE INDEX idx_users_email ON users (email);

-- Trigger to auto-update updated_at on every row change
CREATE OR REPLACE FUNCTION update_updated_at()
    RETURNS TRIGGER AS
$$
BEGIN
    NEW.updated_at = NOW();
RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE
    ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at();