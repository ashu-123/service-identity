package com.common.identity.auth.service;

import com.common.identity.auth.model.entity.RefreshToken;
import com.common.identity.auth.repository.RefreshTokenRepository;
import com.common.identity.config.RefreshTokenProperties;
import com.common.identity.security.RefreshTokenGenerator;
import com.common.identity.security.TokenHashingService;
import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    private final RefreshTokenGenerator refreshTokenGenerator;

    private final TokenHashingService tokenHashingService;

    private final RefreshTokenProperties properties;

    private final RefreshTokenGenerator tokenGenerator;

    @Transactional
    public RefreshTokenCreationResult create(Long userId) {

        String rawToken = refreshTokenGenerator.generate();
        String tokenHash = tokenHashingService.hash(rawToken);
        UUID familyId = UUID.randomUUID();
        var refreshToken = RefreshToken.builder()
                .userId(userId)
                .tokenHash(tokenHash)
                .familyId(familyId)
                .expiresAt(Instant.now().plus(properties.getExpiration()))
                .createdAt(Instant.now())
                .build();

        refreshTokenRepository.save(refreshToken);
        return new RefreshTokenCreationResult(rawToken, refreshToken);
    }

    @Transactional
    public RefreshTokenCreationResult rotate(RefreshToken current) {

        String rawToken = tokenGenerator.generate();
        RefreshToken replacement = RefreshToken.builder()
                        .userId(current.getUserId())
                        .tokenHash(tokenHashingService.hash(rawToken))
                        .familyId(current.getFamilyId())
                        .expiresAt(Instant.now().plus(properties.getExpiration()))
                        .createdAt(Instant.now())
                        .build();

        refreshTokenRepository.saveAndFlush(replacement);
        current.setRevokedAt(Instant.now());
        current.setReplacedByTokenId(replacement.getId());

        refreshTokenRepository.save(current);
        return new RefreshTokenCreationResult(rawToken, replacement);
    }

    @Transactional
    public void revokeFamily(UUID familyId) {

        List<RefreshToken> tokens = refreshTokenRepository.findAllByFamilyId(familyId);

        Instant now = Instant.now();
        for (RefreshToken token : tokens) {
            if (!token.isRevoked()) { token.setRevokedAt(now); }
        }
        refreshTokenRepository.saveAll(tokens);
    }


    public record RefreshTokenCreationResult(String rawToken, RefreshToken entity) { }
}