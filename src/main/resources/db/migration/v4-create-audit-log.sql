-- ============================================================
-- V4: Create audit_log table
-- ============================================================
-- Immutable append-only log of security-relevant events.
-- No updates or deletes should ever be performed on this table.
-- user_id is nullable to capture events for unresolved users
-- (e.g. failed login attempts with an unknown username).
-- ============================================================

CREATE TABLE audit_log
(
    id          UUID                     NOT NULL DEFAULT gen_random_uuid(),
    user_id     UUID,
    event_type  VARCHAR(100)             NOT NULL,
    outcome     VARCHAR(20)              NOT NULL,
    ip_address  VARCHAR(45),
    user_agent  VARCHAR(500),
    detail      TEXT,
    occurred_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT pk_audit_log PRIMARY KEY (id),
    CONSTRAINT chk_audit_log_outcome CHECK (outcome IN ('SUCCESS', 'FAILURE')),
    CONSTRAINT fk_audit_log_user
        FOREIGN KEY (user_id)
            REFERENCES users (id)
            ON DELETE SET NULL
);

-- Lookup audit trail for a specific user
CREATE INDEX idx_al_user_id ON audit_log (user_id);

-- Lookup by event type (e.g. all LOGIN_FAILURE events for alerting)
CREATE INDEX idx_al_event_type ON audit_log (event_type);

-- Time-range queries (e.g. all events in the last 24 hours)
CREATE INDEX idx_al_occurred_at ON audit_log (occurred_at DESC);

-- Composite: all failures for a user within a time window (brute force detection)
CREATE INDEX idx_al_user_failures
    ON audit_log (user_id, occurred_at DESC)
    WHERE outcome = 'FAILURE';

-- ============================================================
-- Seed: event type reference comment
-- ============================================================
-- Expected event_type values (enforced in service layer, not DB):
--   LOGIN_SUCCESS         - Successful login
--   LOGIN_FAILURE         - Bad credentials
--   LOGOUT                - Explicit logout
--   TOKEN_REFRESH         - Access token refreshed
--   PASSWORD_RESET_REQUEST  - Reset email triggered
--   PASSWORD_RESET_SUCCESS  - Password successfully changed
--   ACCOUNT_LOCKED        - Account locked after max failed attempts
--   ACCOUNT_ENABLED       - Account re-enabled by admin
--   USER_CREATED          - New user registered
--   USER_UPDATED          - User details changed
--   USER_DELETED          - User account deleted
-- ============================================================