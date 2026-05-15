package com.template.api.domain;

import org.springframework.data.annotation.Id;
import org.springframework.data.jdbc.core.mapping.AggregateReference;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

/**
 * Immutable append-only audit log entry.
 *
 * Records all security-relevant events across the auth API.
 * Entries are never updated or deleted — the database schema
 * enforces this via ON DELETE SET NULL on the user FK, preserving
 * history even when a user account is removed.
 *
 * userId is nullable to support logging events for unknown usernames
 * (e.g. a LOGIN_FAILURE where the username doesn't exist in the system).
 *
 * Factory methods are provided for each event type to ensure
 * consistent, well-structured entries across the codebase.
 */
@Table("audit_log")
public record AuditLog(

        @Id
        UUID id,

        @Column("user_id")
        AggregateReference<User, UUID> userId,

        @Column("event_type")
        EventType eventType,

        @Column("outcome")
        Outcome outcome,

        @Column("ip_address")
        String ipAddress,

        @Column("user_agent")
        String userAgent,

        @Column("detail")
        String detail,

        @Column("occurred_at")
        Instant occurredAt
) {
    // ----------------------------------------------------------------
    // Event types — mirrors the documented set in V4 migration
    // ----------------------------------------------------------------
    public enum EventType {
        LOGIN_SUCCESS,
        LOGIN_FAILURE,
        LOGOUT,
        TOKEN_REFRESH,
        PASSWORD_RESET_REQUEST,
        PASSWORD_RESET_SUCCESS,
        ACCOUNT_LOCKED,
        ACCOUNT_ENABLED,
        USER_CREATED,
        USER_UPDATED,
        USER_DELETED
    }

    public enum Outcome {
        SUCCESS,
        FAILURE
    }

    // ----------------------------------------------------------------
    // Core factory method
    // ----------------------------------------------------------------

    private static AuditLog of(UUID userId, EventType eventType, Outcome outcome,
                               String ipAddress, String userAgent,
                               String detail, Instant now) {
        return new AuditLog(
                null,
                userId != null ? AggregateReference.to(userId) : null,
                eventType,
                outcome,
                ipAddress,
                userAgent,
                detail,
                now
        );
    }

    // ----------------------------------------------------------------
    // Auth event factories
    // ----------------------------------------------------------------

    public static AuditLog loginSuccess(UUID userId, String ipAddress, String userAgent, Instant now) {
        return of(userId, EventType.LOGIN_SUCCESS, Outcome.SUCCESS,
                ipAddress, userAgent, null, now);
    }

    public static AuditLog loginFailure(UUID userId, String ipAddress, String userAgent, String detail, Instant now) {
        return of(userId, EventType.LOGIN_FAILURE, Outcome.FAILURE,
                ipAddress, userAgent, detail, now);
    }

    public static AuditLog logout(UUID userId, String ipAddress, String userAgent, Instant now) {
        return of(userId, EventType.LOGOUT, Outcome.SUCCESS,
                ipAddress, userAgent, null, now);
    }

    public static AuditLog tokenRefresh(UUID userId, String ipAddress, String userAgent, Instant now) {
        return of(userId, EventType.TOKEN_REFRESH, Outcome.SUCCESS,
                ipAddress, userAgent, null, now);
    }

    // ----------------------------------------------------------------
    // Password reset event factories
    // ----------------------------------------------------------------

    public static AuditLog passwordResetRequest(UUID userId, String ipAddress, String userAgent, Instant now) {
        return of(userId, EventType.PASSWORD_RESET_REQUEST, Outcome.SUCCESS,
                ipAddress, userAgent, null, now);
    }

    public static AuditLog passwordResetSuccess(UUID userId, String ipAddress, String userAgent, Instant now) {
        return of(userId, EventType.PASSWORD_RESET_SUCCESS, Outcome.SUCCESS,
                ipAddress, userAgent, null, now);
    }

    // ----------------------------------------------------------------
    // Account management event factories
    // ----------------------------------------------------------------

    public static AuditLog accountLocked(UUID userId, String ipAddress, String userAgent, Instant now) {
        return of(userId, EventType.ACCOUNT_LOCKED, Outcome.FAILURE,
                ipAddress, userAgent, "Account locked after max failed attempts", now);
    }

    public static AuditLog accountEnabled(UUID userId, String ipAddress, String userAgent, Instant now) {
        return of(userId, EventType.ACCOUNT_ENABLED, Outcome.SUCCESS,
                ipAddress, userAgent, null, now);
    }

    public static AuditLog userCreated(UUID userId, String ipAddress, String userAgent, Instant now) {
        return of(userId, EventType.USER_CREATED, Outcome.SUCCESS,
                ipAddress, userAgent, null, now);
    }

    public static AuditLog userUpdated(UUID userId, String ipAddress, String userAgent, Instant now) {
        return of(userId, EventType.USER_UPDATED, Outcome.SUCCESS,
                ipAddress, userAgent, null, now);
    }

    public static AuditLog userDeleted(UUID userId, String ipAddress, String userAgent, Instant now) {
        return of(userId, EventType.USER_DELETED, Outcome.SUCCESS,
                ipAddress, userAgent, null, now);
    }
}
