package com.template.api.domain;

import lombok.Builder;
import lombok.With;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.util.UUID;
import java.time.Instant;

@Table("users")
@Builder(toBuilder = true)
public record User(
        @Id
        UUID id,

        @Column("username")
        String username,

        @Column("email")
        String email,

        // Password is always stored as a BCrypt hash and not plain text
        @Column("password_hash")
        String passwordHash,

        @Column("first_name")
        String firstName,

        @Column("last_name")
        String lastName,

        @Column("role")
        Role role,

        @Column("enabled")
        boolean enabled,

        @Column("account_locked")
        boolean accountLocked,

        @Column("failed_login_attempts")
        int failedLoginAttempts,

        @Column("last_login_at")
        Instant lastLoginAt,

        @CreatedDate
        @Column("created_at")
        Instant createdAt,

        @LastModifiedDate
        @Column("updated_at")
        Instant updatedAt
) {
    public static final int MAX_FAILED_LOGIN_ATTEMPTS = 5;

    /**
     * Factory method to create a new User instance on registration.
     * Sets safe defaults: USER role, enabled, not locked, zero failed attempts
     */
    public static User register(String username, String email, String passwordHash, String firstName, String lastName) {
        return User.builder()
                .username(username)
                .email(email)
                .passwordHash(passwordHash)
                .firstName(firstName)
                .lastName(lastName)
                .role(Role.USER)
                .enabled(true)
                .accountLocked(false)
                .failedLoginAttempts(0)
                .build();
    }

    /**
     * Factory method to register user as an admin
     */
    public static User registerAsAdmin(String username, String email, String passwordHash, String firstName, String lastName) {
        return User.builder()
                .username(username)
                .email(email)
                .passwordHash(passwordHash)
                .firstName(firstName)
                .lastName(lastName)
                .role(Role.ADMIN)
                .enabled(true)
                .accountLocked(false)
                .failedLoginAttempts(0)
                .build();
    }

    /** Returns a user with failedLoginAttempts incremented by 1 for each failed attempt **/
    public User incrementFailedLoginAttempts() {
        return this.toBuilder()
                .failedLoginAttempts(this.failedLoginAttempts + 1)
                .build();
    }

    /** Returns a user with the account locked and failed attempts at max **/
    public User lockAccount() {
        return this.toBuilder()
                .accountLocked(true)
                .failedLoginAttempts(MAX_FAILED_LOGIN_ATTEMPTS)
                .build();
    }

    /** Returns a user with failed attempts reset and account unlocked **/
    public User unlockAccount() {
        return this.toBuilder()
                .accountLocked(false)
                .failedLoginAttempts(0)
                .build();
    }

    /** Returns a user with last login time recorded **/
    public User recordLastLogin() {
        return this.toBuilder()
                .lastLoginAt(Instant.now())
                .build();
    }

    /** If user should be locked depending on if user has exceeded max failed login attempts **/
    public boolean shouldBeLocked() {
        // account locking itself is applied at the service layer
        return this.failedLoginAttempts >= MAX_FAILED_LOGIN_ATTEMPTS;
    }

    public enum Role {
        USER, ADMIN
    }
}
