package com.template.api.repository;

import com.template.api.domain.AuditLog;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Repository for {@link AuditLog}.
 *
 * Append-only — no update or delete methods are exposed.
 * All writes go through save(). Reads support security monitoring,
 * brute force detection, and user activity queries.
 *
 * The audit log is intentionally never purged via this repository.
 * Retention policy (e.g. archiving rows older than 90 days) should
 * be handled at the infrastructure level, not in application code.
 */
@Repository
public interface AuditLogRepository extends CrudRepository<AuditLog, UUID> {

    // ----------------------------------------------------------------
    // User activity queries
    // ----------------------------------------------------------------

    /**
     * Fetch all audit events for a specific user, most recent first.
     * Used to display a user's security activity history.
     */
    @Query("SELECT * FROM audit_log " +
            "WHERE user_id = :userId " +
            "ORDER BY occurred_at DESC " +
            "LIMIT :limit")
    List<AuditLog> findRecentByUserId(UUID userId, int limit);

    /**
     * Fetch all audit events for a user within a time window.
     * Used for targeted investigations.
     */
    @Query("SELECT * FROM audit_log " +
            "WHERE user_id = :userId " +
            "AND occurred_at BETWEEN :from AND :to " +
            "ORDER BY occurred_at DESC")
    List<AuditLog> findByUserIdBetween(UUID userId, Instant from, Instant to);

    // ----------------------------------------------------------------
    // Security monitoring queries
    // ----------------------------------------------------------------

    /**
     * Count failed login attempts for a user since a given time.
     * Primary input for brute force detection in the service layer.
     */
    @Query("SELECT COUNT(*) FROM audit_log " +
            "WHERE user_id = :userId " +
            "AND event_type = 'LOGIN_FAILURE' " +
            "AND outcome = 'FAILURE' " +
            "AND occurred_at > :since")
    int countFailedLoginAttemptsSince(UUID userId, Instant since);

    /**
     * Count failed login attempts by IP address since a given time.
     * Used to detect distributed brute force across multiple usernames.
     */
    @Query("SELECT COUNT(*) FROM audit_log " +
            "WHERE ip_address = :ipAddress " +
            "AND event_type = 'LOGIN_FAILURE' " +
            "AND occurred_at > :since")
    int countFailedLoginAttemptsByIpSince(String ipAddress, Instant since);

    /**
     * Fetch all failure events for a user since a given time.
     * Used to build a security alert picture.
     */
    @Query("SELECT * FROM audit_log " +
            "WHERE user_id = :userId " +
            "AND outcome = 'FAILURE' " +
            "AND occurred_at > :since " +
            "ORDER BY occurred_at DESC")
    List<AuditLog> findFailuresByUserIdSince(UUID userId, Instant since);

    /**
     * Fetch all events of a given type across all users within a time window.
     * Used for system-level monitoring (e.g. spike in LOGIN_FAILURE events).
     */
    @Query("SELECT * FROM audit_log " +
            "WHERE event_type = :#{#eventType.name()} " +
            "AND occurred_at > :since " +
            "ORDER BY occurred_at DESC " +
            "LIMIT :limit")
    List<AuditLog> findByEventTypeSince(AuditLog.EventType eventType, Instant since, int limit);
}
