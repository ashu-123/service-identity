package com.common.identity.auth.model.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "password_reset_tokens",
        uniqueConstraints = { @UniqueConstraint(name = "uk_password_reset_token_hash", columnNames = "token_hash")},
        indexes = {
                @Index(name = "idx_password_reset_user_id", columnList = "user_id"),
                @Index(name = "idx_password_reset_expires_at", columnList = "expires_at")
        })
@Getter
@Setter
@NoArgsConstructor
public class PasswordResetToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "token_hash", nullable = false, unique = true, length = 64)
    private String tokenHash;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;
}