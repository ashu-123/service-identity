package com.common.identity.auth.service;

import com.common.identity.auth.config.PasswordResetProperties;
import com.common.identity.auth.model.dto.PasswordResetConfirmRequestDto;
import com.common.identity.auth.model.dto.PasswordResetRequestedEventDto;
import com.common.identity.auth.model.entity.PasswordResetToken;
import com.common.identity.auth.repository.PasswordResetTokenRepository;
import com.common.identity.exception.InvalidPasswordResetTokenException;
import com.common.identity.refresh.service.RefreshTokenService;
import com.common.identity.refresh.utils.RefreshTokenGenerator;
import com.common.identity.security.TokenHashingService;
import com.common.identity.user.model.entity.User;
import com.common.identity.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Locale;

@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenGenerator tokenGenerator;
    private final TokenHashingService tokenHashService;
    private final PasswordResetProperties properties;
    private final ApplicationEventPublisher eventPublisher;
    private final RefreshTokenService refreshTokenService;
    private final Clock clock;

    @Transactional
    public void requestPasswordReset(String rawEmail) {

        String email = normalizeEmail(rawEmail);

        /*
         * We intentionally don't expose whether the
         * email exists.
         */
        User user = userRepository
                        .findByEmailIgnoreCase(email)
                        .orElse(null);

        if (user == null) { return; }

        /*
         * If this user doesn't have a local password,
         * there is nothing to reset.
         *
         * We still return normally to prevent
         * account enumeration.
         */
        if (user.getPasswordHash() == null) {
            return;
        }

        /*
         * Invalidate any previous reset token.
         */
        passwordResetTokenRepository.deleteByUserId(user.getId());

        /*
         * Generate cryptographically secure token.
         */
        String rawToken = tokenGenerator.generate();

        /*
         * Store only the SHA-256 hash.
         */
        String tokenHash = tokenHashService.hash(rawToken);

        Instant now = Instant.now(clock);
        PasswordResetToken resetToken = new PasswordResetToken();
        resetToken.setUserId(user.getId());

        resetToken.setTokenHash(tokenHash);
        resetToken.setCreatedAt(now);
        resetToken.setExpiresAt(now.plus(properties.expiration()));
        passwordResetTokenRepository.save(resetToken);

        String resetUrl = buildResetUrl(rawToken);

        /*
         * Email is sent AFTER the transaction commits.
         */
        eventPublisher.publishEvent(new PasswordResetRequestedEventDto(email, resetUrl));
    }

    @Transactional
    public void resetPassword(PasswordResetConfirmRequestDto request) {

        String tokenHash = tokenHashService.hash(request.token());

        /*
         * SELECT ... FOR UPDATE
         */
        var resetToken = passwordResetTokenRepository
                        .findByTokenHashForUpdate(tokenHash)
                        .orElseThrow(InvalidPasswordResetTokenException::new);

        Instant now = Instant.now(clock);

        /*
         * Token expired.
         */
        if (!resetToken.getExpiresAt().isAfter(now)) {
            throw new InvalidPasswordResetTokenException();
        }

        /*
         * Load the actual User.
         */
        User user = userRepository
                        .findById(resetToken.getUserId())
                        .orElseThrow(InvalidPasswordResetTokenException::new);

        /*
         * Hash the new password using the same
         * PasswordEncoder used during registration/login.
         */
        String newPasswordHash = passwordEncoder.encode(request.newPassword());

        user.setPasswordHash(newPasswordHash);
        user.setUpdatedAt(OffsetDateTime.now());
        userRepository.save(user);

        /*
         * Revoke ALL active refresh tokens for
         * this user.
         */
        refreshTokenService.revokeAllForUser(user.getId());

        /*
         * Consume the password-reset token.
         *
         * This happens in the SAME transaction as
         * the password update.
         */
        passwordResetTokenRepository.delete(resetToken);
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private String buildResetUrl(String rawToken) {

        return "http://localhost:4200"
                + "/reset-password?token="
                + URLEncoder.encode(rawToken, StandardCharsets.UTF_8);
    }
}