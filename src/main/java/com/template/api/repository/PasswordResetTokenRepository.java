package com.template.api.repository;

import com.template.api.domain.PasswordResetToken;
import org.springframework.data.jdbc.repository.query.Modifying;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for {@link PasswordResetToken}.
 *
 * Tokens are looked up by their hash — the raw token is never persisted.
 * The database partial unique index ensures only one active (unused)
 * token exists per user at a time, but we also invalidate old tokens
 * explicitly here as a belt-and-braces measure.
 */
@Repository
public interface PasswordResetTokenRepository extends CrudRepository<PasswordResetToken, UUID> {

    // ----------------------------------------------------------------
    // Lookup queries
    // ----------------------------------------------------------------

    /**
     * Find a token by its hash.
     * Primary lookup on password reset confirmation.
     */
    @Query("SELECT * FROM password_reset_tokens WHERE token_hash = :tokenHash")
    Optional<PasswordResetToken> findByTokenHash(String tokenHash);

    /**
     * Find the active (unused, unexpired) token for a user.
     * Used to check whether a valid reset is already in progress.
     */
    @Query("SELECT * FROM password_reset_tokens " +
            "WHERE user_id = :userId " +
            "AND used_at IS NULL " +
            "AND expires_at > :now")
    Optional<PasswordResetToken> findActiveTokenByUserId(UUID userId, Instant now);

    // ----------------------------------------------------------------
    // Update / cleanup queries
    // ----------------------------------------------------------------

    /**
     * Mark a token as used at the given timestamp.
     * Called immediately after a successful password reset.
     */
    @Modifying
    @Query("UPDATE password_reset_tokens SET used_at = :usedAt WHERE id = :id")
    void markTokenUsed(UUID id, Instant usedAt);

    /**
     * Invalidate all unused tokens for a user.
     * Called when a new reset is requested, clearing any prior active token
     * before the database partial unique index would reject the insert.
     */
    @Modifying
    @Query("UPDATE password_reset_tokens SET used_at = NOW() " +
            "WHERE user_id = :userId AND used_at IS NULL")
    void invalidateAllActiveTokensForUser(UUID userId);

    /**
     * Delete all expired and used tokens for a user.
     * Called as a housekeeping step — can also be scheduled periodically.
     */
    @Modifying
    @Query("DELETE FROM password_reset_tokens " +
            "WHERE user_id = :userId " +
            "AND (used_at IS NOT NULL OR expires_at < :now)")
    void deleteExpiredAndUsedTokensForUser(UUID userId, Instant now);
}
