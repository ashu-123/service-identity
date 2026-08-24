package com.common.identity.oauth.repository;

import com.common.identity.oauth.model.entity.ExternalIdentity;
import com.common.identity.oauth.model.type.IdentityProvider;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ExternalIdentityRepository extends JpaRepository<ExternalIdentity, UUID> {

    Optional<ExternalIdentity> findByProviderAndProviderSubject(IdentityProvider provider, String providerSubject);

    boolean existsByProviderAndProviderSubject(IdentityProvider provider, String providerSubject);

    List<ExternalIdentity> findAllByUserId(UUID userId);
}