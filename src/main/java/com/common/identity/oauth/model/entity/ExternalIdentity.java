package com.common.identity.oauth.model.entity;

import com.common.identity.oauth.model.type.IdentityProvider;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "external_identities",
        uniqueConstraints = {
        @UniqueConstraint(name = "uk_external_identity_provider_subject",
                columnNames = { "provider", "provider_subject" })
        })
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ExternalIdentity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Enumerated(EnumType.STRING)
    @Column(name = "provider", nullable = false, length = 50)
    private IdentityProvider provider;

    @Column(name = "provider_subject", nullable = false, length = 255)
    private String providerSubject;

    @Column(name = "email", length = 320)
    private String email;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;
}