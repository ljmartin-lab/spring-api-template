package com.template.api.repository;

import com.template.api.domain.User;
import org.springframework.data.jdbc.repository.query.Modifying;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for {@link User} aggregate.
 *
 * Spring Data JDBC provides save(), findById(), delete(), existsById()
 * for free via CrudRepository. All other queries are explicit @Query
 * methods — no derived query magic, no surprises.
 *
 * Queries use snake_case column names to match the database schema.
 */
@Repository
public interface UserRepository extends CrudRepository<User, UUID> {

    // ----------------------------------------------------------------
    // Lookup queries
    // ----------------------------------------------------------------

    /**
     * Find a user by their username.
     * Primary lookup path for login.
     */
    @Query("SELECT * FROM users WHERE username = :username")
    Optional<User> findByUsername(String username);

    /**
     * Find a user by their email address.
     * Used for password reset flow and duplicate checks.
     */
    @Query("SELECT * FROM users WHERE email = :email")
    Optional<User> findByEmail(String email);

    /**
     * Check whether a username is already taken.
     * Used during registration to fail fast before hashing.
     */
    @Query("SELECT EXISTS(SELECT 1 FROM users WHERE username = :username)")
    boolean existsByUsername(String username);

    /**
     * Check whether an email is already registered.
     * Used during registration.
     */
    @Query("SELECT EXISTS(SELECT 1 FROM users WHERE email = :email)")
    boolean existsByEmail(String email);

    // ----------------------------------------------------------------
    // Update queries — targeted updates avoid loading and re-saving
    // the full aggregate for high-frequency operations
    // ----------------------------------------------------------------

    /**
     * Increment failed login attempts by one.
     * Called on every failed login attempt before locking check.
     */
    @Modifying
    @Query("UPDATE users SET failed_login_attempts = failed_login_attempts + 1, " +
            "updated_at = NOW() WHERE id = :id")
    void incrementFailedLoginAttempts(UUID id);

    /**
     * Reset failed login attempts to zero and unlock the account.
     * Called on successful login.
     */
    @Modifying
    @Query("UPDATE users SET failed_login_attempts = 0, account_locked = FALSE, " +
            "updated_at = NOW() WHERE id = :id")
    void resetFailedLoginAttempts(UUID id);

    /**
     * Lock the user account.
     * Called when failed_login_attempts reaches User.MAX_FAILED_ATTEMPTS.
     */
    @Modifying
    @Query("UPDATE users SET account_locked = TRUE, updated_at = NOW() WHERE id = :id")
    void lockAccount(UUID id);

    /**
     * Record a successful login timestamp.
     * Called immediately after a successful authentication.
     */
    @Modifying
    @Query("UPDATE users SET last_login_at = :lastLoginAt, " +
            "failed_login_attempts = 0, account_locked = FALSE, " +
            "updated_at = NOW() WHERE id = :id")
    void recordSuccessfulLogin(UUID id, Instant lastLoginAt);

    /**
     * Update the user's hashed password.
     * Called at the end of a successful password reset flow.
     */
    @Modifying
    @Query("UPDATE users SET password_hash = :passwordHash, updated_at = NOW() WHERE id = :id")
    void updatePasswordHash(UUID id, String passwordHash);
}
