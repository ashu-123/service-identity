package com.common.identity.oauth.service;

import com.common.identity.auth.model.dto.AuthResponseDto;
import com.common.identity.refresh.service.RefreshTokenService;
import com.common.identity.exception.AccountLinkRequiredException;
import com.common.identity.jwt.JwtService;
import com.common.identity.oauth.model.dto.OAuthLoginResultDto;
import com.common.identity.oauth.model.entity.ExternalIdentity;
import com.common.identity.oauth.repository.ExternalIdentityRepository;
import com.common.identity.security.UserPrincipal;
import com.common.identity.user.model.entity.User;
import com.common.identity.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Optional;

import static com.common.identity.oauth.model.type.IdentityProvider.GOOGLE;

@Service
@RequiredArgsConstructor
public class OAuth2IdentityService {

    private final ExternalIdentityRepository externalIdentityRepository;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    @Transactional
    public OAuthLoginResultDto authenticate(OidcUser oidcUser) {

        String providerSubject = oidcUser.getSubject();
        String email = oidcUser.getEmail();
        var externalIdentity = externalIdentityRepository.findByProviderAndProviderSubject(GOOGLE, providerSubject)
                .orElse(null);

        User user;

        /*
         * Case 1:
         *
         * Google identity already exists.
         *
         * GOOGLE + providerSubject uniquely identifies
         * the external identity.
         */
        if (externalIdentity != null) {
            user = userRepository.findById(externalIdentity.getUserId())
                    .orElseThrow(() -> new IllegalStateException("External identity references " + "a non-existent user"));
        } else {

            /*
             * Case 2:
             *
             * Google identity is being used for the first time.
             */
            user = findOrCreateUser(oidcUser);

            externalIdentity = ExternalIdentity.builder()
                    .userId(user.getId())
                    .provider(GOOGLE)
                    .providerSubject(providerSubject)
                    .email(email)
                    .createdAt(Instant.now())
                    .updatedAt(Instant.now())
                    .build();

            externalIdentityRepository.save(externalIdentity);
        }

        /*
         * At this point we have our application's User.
         *
         * From here onwards, Google is no longer involved.
         *
         * We issue our own access + refresh tokens.
         */
        return issueApplicationTokens(user);
    }

    private User findOrCreateUser(OidcUser oidcUser) {

        String email = oidcUser.getEmail();

        /*
         * Email is useful for detecting an existing
         * application account, but NOT as the identity
         * key for Google.
         */
        Optional<User> existingUser = userRepository.findByEmailIgnoreCase(email);
        if (existingUser.isPresent()) {

            /*
             * Do NOT silently associate Google with an
             * existing password account merely because
             * the email matches.
             *
             * Account linking should be an explicit,
             * authenticated operation.
             */
            throw new AccountLinkRequiredException("""
                    An account already exists with this email.
                    Sign in using the existing authentication method
                    and link your Google account.""");
        }

        User user = User.builder()
                        .email(email)
                        .firstName(oidcUser.getFullName()) // fix it
                        .lastName(oidcUser.getFullName())
                        .enabled(true)
                        .createdAt(OffsetDateTime.now())
                        .updatedAt(OffsetDateTime.now())
                        .build();

        return userRepository.save(user);
    }

    private OAuthLoginResultDto issueApplicationTokens(User user) {

        UserPrincipal principal = UserPrincipal.from(user);
        /*
         * Generate our own RS256 access token.
         *
         * This is the token that AutoCaption and RCE
         * will validate.
         */
        String accessToken = jwtService.generateAccessToken(principal);

        /*
         * Generate our own refresh token.
         *
         * RefreshTokenService is responsible for:
         *   - secure random generation
         *   - hashing
         *   - persistence
         *   - family creation
         */
        var refreshToken = refreshTokenService.create(user.getId());
        var authResponse = AuthResponseDto.builder()
                .accessToken(accessToken)
                .tokenType("Bearer")
                .expiresIn(jwtService.getAccessTokenExpirationSeconds())
                .build();

        return new OAuthLoginResultDto(user.getId(), authResponse, refreshToken.rawToken());
    }
}