package com.common.identity.refresh.service;

import com.common.identity.auth.model.dto.AuthResponseDto;
import com.common.identity.refresh.repository.RefreshTokenRepository;
import com.common.identity.exception.InvalidRefreshTokenException;
import com.common.identity.exception.RefreshTokenReplayException;
import com.common.identity.jwt.JwtService;
import com.common.identity.security.CustomUserDetailsService;
import com.common.identity.security.TokenHashingService;
import com.common.identity.security.UserPrincipal;
import com.common.identity.user.model.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class RefreshService {

    private final RefreshTokenService refreshTokenService;
    private final TokenHashingService tokenHashingService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final CustomUserDetailsService userDetailsService;
    private final JwtService jwtService;

    @Transactional
    public RefreshResult refresh(String rawRefreshToken) {

        if (rawRefreshToken == null || rawRefreshToken.isBlank()) { throw new InvalidRefreshTokenException(); }

        String tokenHash = tokenHashingService.hash(rawRefreshToken);

        var currentRefreshToken = refreshTokenRepository
                        .findByTokenHash(tokenHash)
                        .orElseThrow(InvalidRefreshTokenException::new);

        /*
         * Replay detection.
         */
        if (currentRefreshToken.isRevoked()) {
            refreshTokenService.revokeFamily(currentRefreshToken.getFamilyId());
            throw new RefreshTokenReplayException();
        }

        /*
         * Expired token.
         */
        if (currentRefreshToken.isExpired()) {
            throw new InvalidRefreshTokenException();
        }

        /*
         * Generate new access token.
         */
        User user = userDetailsService.getUserById(currentRefreshToken.getUserId());
        UserPrincipal principal = UserPrincipal.from(user);
        String accessToken = jwtService.generateAccessToken(principal);

        /*
         * Rotate refresh token.
         */
        var newRefreshToken = refreshTokenService.rotate(currentRefreshToken);

        var response = AuthResponseDto.builder()
                        .accessToken(accessToken)
                        .tokenType("Bearer")
                        .expiresIn(jwtService.getAccessTokenExpirationSeconds())
                        .build();

        return new RefreshResult(response, newRefreshToken.rawToken()
        );
    }


    public record RefreshResult (AuthResponseDto authResponseDto, String refreshToken){}
}
