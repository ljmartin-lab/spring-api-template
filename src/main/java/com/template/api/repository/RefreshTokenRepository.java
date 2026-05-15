package com.template.api.repository;

import com.template.api.domain.RefreshToken;
import org.springframework.data.jdbc.repository.query.Modifying;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for {@link RefreshToken}.
 *
 * Supports token rotation (revoke old, issue new), multi-session
 * management (list/revoke all sessions for a user), and housekeeping
 * (delete expired/revoked tokens).
 *
 * Raw tokens are never stored — only their SHA-256 hash.
 */
@Repository
public interface RefreshTokenRepository extends CrudRepository<RefreshToken, UUID> {

    // ----------------------------------------------------------------
    // Lookup queries
    // ----------------------------------------------------------------

    /**
     * Find a refresh token by its hash.
     * Primary lookup on every token refresh request.
     */
    @Query("SELECT * FROM refresh_tokens WHERE token_hash = :tokenHash")
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    /**
     * Find all active (non-revoked, non-expired) sessions for a user.
     * Used for session management — listing active devices.
     */
    @Query("SELECT * FROM refresh_tokens " +
            "WHERE user_id = :userId " +
            "AND revoked_at IS NULL " +
            "AND expires_at > :now " +
            "ORDER BY created_at DESC")
    List<RefreshToken> findActiveTokensByUserId(UUID userId, Instant now);

    /**
     * Count active sessions for a user.
     * Can be used to enforce a max concurrent sessions policy.
     */
    @Query("SELECT COUNT(*) FROM refresh_tokens " +
            "WHERE user_id = :userId " +
            "AND revoked_at IS NULL " +
            "AND expires_at > :now")
    int countActiveSessionsByUserId(UUID userId, Instant now);

    // ----------------------------------------------------------------
    // Revocation queries
    // ----------------------------------------------------------------

    /**
     * Revoke a single token by its ID.
     * Called during token rotation — the old token is revoked
     * before a new one is issued.
     */
    @Modifying
    @Query("UPDATE refresh_tokens SET revoked_at = :revokedAt WHERE id = :id")
    void revokeById(UUID id, Instant revokedAt);

    /**
     * Revoke all active tokens for a user.
     * Called on logout-all / account lock / password reset success.
     */
    @Modifying
    @Query("UPDATE refresh_tokens SET revoked_at = :revokedAt " +
            "WHERE user_id = :userId AND revoked_at IS NULL")
    void revokeAllByUserId(UUID userId, Instant revokedAt);

    // ----------------------------------------------------------------
    // Housekeeping queries
    // ----------------------------------------------------------------

    /**
     * Delete all tokens for a user that are expired or already revoked.
     * Called periodically or on login to keep the table lean.
     */
    @Modifying
    @Query("DELETE FROM refresh_tokens " +
            "WHERE user_id = :userId " +
            "AND (revoked_at IS NOT NULL OR expires_at < :now)")
    void deleteExpiredAndRevokedByUserId(UUID userId, Instant now);

    /**
     * Delete all tokens for a user.
     * Called when a user account is deleted.
     */
    @Modifying
    @Query("DELETE FROM refresh_tokens WHERE user_id = :userId")
    void deleteAllByUserId(UUID userId);
}
