package com.template.api.domain;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.jdbc.core.mapping.AggregateReference;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

/**
 * TODO: understand what is being done and simplify comments accordingly
 * Represents a persisted refresh token for a user session.
 *
 * Access tokens are short-lived (15 min) and stateless — they are
 * not stored here. Refresh tokens are long-lived (7 days) and stored
 * so they can be explicitly revoked.
 *
 * Token rotation is enforced by the service layer:
 *   1. Incoming refresh token is validated and revoked (revoked_at set)
 *   2. A new refresh token is issued and persisted
 *   3. A new access token is returned alongside it
 *
 * Multiple active sessions per user are supported (one row per device).
 * The raw token is never stored — only its SHA-256 hash.
 */
@Table("refresh_tokens")
public record RefreshToken(

        @Id
        UUID id,

        @Column("user_id")
        AggregateReference<User, UUID> userId,

        @Column("token_hash")
        String tokenHash,

        @Column("device_info")
        String deviceInfo,

        @Column("ip_address")
        String ipAddress,

        @Column("expires_at")
        Instant expiresAt,

        @Column("revoked_at")
        Instant revokedAt,

        @CreatedDate
        @Column("created_at")
        Instant createdAt
) {
    /** Default TTL is 7 days */
    public static final long TTL_DAYS = 7;

    /**
     * Factory method to create a new refresh token for a user session.
     */
    public static RefreshToken create(UUID userId, String tokenHash,
                                      String deviceInfo, String ipAddress,
                                      Instant now) {
        return new RefreshToken(
                null,
                AggregateReference.to(userId),
                tokenHash,
                deviceInfo,
                ipAddress,
                now.plusSeconds(TTL_DAYS * 24 * 60 * 60),
                null,
                now
        );
    }

    /** Whether this token has passed its expiry time. */
    public boolean isExpired(Instant now) {
        return now.isAfter(this.expiresAt);
    }

    /** Whether this token has been explicitly revoked. */
    public boolean isRevoked() {
        return this.revokedAt != null;
    }

    /** Whether this token is valid — not expired and not revoked. */
    public boolean isValid(Instant now) {
        return !isExpired(now) && !isRevoked();
    }

    /** Returns a new token marked as revoked at the given time. */
    public RefreshToken revoke(Instant revokedAt) {
        return new RefreshToken(
                this.id,
                this.userId,
                this.tokenHash,
                this.deviceInfo,
                this.ipAddress,
                this.expiresAt,
                revokedAt,
                this.createdAt
        );
    }
}
