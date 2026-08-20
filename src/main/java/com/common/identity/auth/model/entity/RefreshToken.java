package com.common.identity.auth.model.entity;

import jakarta.persistence.*;

import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "refresh_tokens",
        indexes = {
            @Index(name = "idx_refresh_token_hash", columnList = "token_hash", unique = true),
            @Index(name = "idx_refresh_token_family_id", columnList = "family_id"),
            @Index(name = "idx_refresh_token_user_id", columnList = "user_id")
        })
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * User who owns this refresh-token.
     *
     * We deliberately store the user ID rather than a JPA
     * relationship to User. The refresh-token subsystem doesn't
     * need to navigate the User entity.
     */
    @Column(name = "user_id", nullable = false)
    private Long userId;

    /**
     * SHA-256 hash of the actual refresh token.
     *
     * The raw token is NEVER stored in the database.
     */
    @Column(name = "token_hash", nullable = false, unique = true, length = 64)
    private String tokenHash;

    /**
     * All refresh tokens generated from the same login session
     * belong to one family.
     */
    @Column(name = "family_id", nullable = false)
    private UUID familyId;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    /**
     * NULL means currently active.
     */
    @Column(name = "revoked_at")
    private Instant revokedAt;

    /**
     * If R1 was rotated into R2:
     *
     * R1.replacedByTokenId = R2.id
     */
    @Column(name = "replaced_by_token_id")
    private UUID replacedByTokenId;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }

    public boolean isExpired() {
        return expiresAt.isBefore(Instant.now());
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public boolean isActive() {
        return !isRevoked() && !isExpired();
    }
}