package com.template.api.domain;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.jdbc.core.mapping.AggregateReference;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

/**
 * Represents a short-lived password reset token.
 *
 * The raw token is never stored — only its SHA-256 hash and is generated and returned to the caller once,
 * then discarded. On confirmation, the incoming token is hashed and looked up against this record.
 *
 * Only one active (unused) token per user is permitted at a time, enforced by a partial unique index in the database.
 */
@Table("password_reset_tokens")
public record PasswordResetToken(
        @Id
        UUID id,

        // maps user id to user aggregate
        @Column("user_id")
        AggregateReference<User, UUID> userId,

        @Column("token_hash")
        String tokenHash,

        @Column("expires_at")
        Instant expiresAt,

        @Column("used_at")
        Instant usedAt,

        @CreatedDate
        @Column("created_at")
        Instant createdAt
) {
        /** The default time to live is 60 minutes **/
        public static final int DEFAULT_TTL_MINUTES = 60;

        /**
         * Factory method to create a new PasswordResetToken instance for given user.
         */
        public static PasswordResetToken createTokenForUser(UUID userId, String tokenHash, Instant now) {
                return new PasswordResetToken(
                        null,
                        AggregateReference.to(userId),
                        tokenHash,
                        now.plusSeconds(DEFAULT_TTL_MINUTES * 60),
                        null,
                        now);
        }

        /** Determine if the token is expired **/
        public boolean isExpired(Instant now) {
                return now.isAfter(this.expiresAt);
        }

        /** Determine if the token has been used **/
        public boolean isUsed() {
                return this.usedAt != null;
        }

        /** Determine if the token is still valid at the given time **/
        public boolean isValid(Instant now) {
                return !isExpired(now) && !isUsed();
        }

        /** Returns a new token marked as used at the given time. */
        public PasswordResetToken markUsed(Instant usedAt) {
                return new PasswordResetToken(
                        this.id,
                        this.userId,
                        this.tokenHash,
                        this.expiresAt,
                        usedAt,
                        this.createdAt
                );
        }
}
