package com.common.identity.auth.service;

import com.common.identity.auth.config.EmailVerificationProperties;
import com.common.identity.auth.model.dto.EmailVerificationRequestDto;
import com.common.identity.auth.model.dto.SignUpRequestDto;
import com.common.identity.auth.model.entity.EmailVerification;
import com.common.identity.auth.repository.EmailVerificationRepository;
import com.common.identity.exception.EmailAlreadyRegisteredException;
import com.common.identity.exception.InvalidEmailVerificationTokenException;
import com.common.identity.oauth.utils.OAuthExchangeCodeGenerator;
import com.common.identity.role.model.entity.Role;
import com.common.identity.role.repository.RoleRepository;
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
public class EmailVerificationService {

    private final EmailVerificationRepository emailVerificationRepository;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final OAuthExchangeCodeGenerator tokenGenerator;
    private final TokenHashingService tokenHashService;
    private final EmailService emailService;
    private final ApplicationEventPublisher eventPublisher;
    private final EmailVerificationProperties properties;
    private final Clock clock;

    private static final String DEFAULT_ROLE = "USER";

    @Transactional
    public void initiateRegistration(SignUpRequestDto request) {

        String email = request.getEmail().trim().toLowerCase(Locale.ROOT);
        if (userRepository.existsByEmailIgnoreCase(email)) {
//            throw new EmailAlreadyRegisteredException();
            throw new RuntimeException("Email already registered");
        }

        emailVerificationRepository.deleteByEmail(email);
        String passwordHash = passwordEncoder.encode(request.getPassword());
        String rawToken = tokenGenerator.generate();
        String tokenHash = tokenHashService.hash(rawToken);

        Instant now = Instant.now(clock);

        EmailVerification verification = new EmailVerification();
        verification.setEmail(email);
        verification.setPasswordHash(passwordHash);
        verification.setName(request.getFirstName() + " " + request.getPassword());
        verification.setTokenHash(tokenHash);
        verification.setCreatedAt(now);
        verification.setExpiresAt(now.plus(properties.getExpiration()));

        emailVerificationRepository.save(verification);
        String verificationUrl = buildVerificationUrl(rawToken);

        eventPublisher.publishEvent(new EmailVerificationRequestDto(email, verificationUrl));
    }

    @Transactional
    public void verifyEmail(String rawToken) {

        String tokenHash = tokenHashService.hash(rawToken);
        var verification = emailVerificationRepository.findByTokenHashForUpdate(tokenHash)
                .orElseThrow(() -> new InvalidEmailVerificationTokenException("Email verification token is invalid or expired"));

        Instant now = Instant.now(clock);
        if (verification.getExpiresAt().isBefore(now)) {
            throw new InvalidEmailVerificationTokenException("Email verification token is invalid or expired");
        }

        /*
         * Extra defense against registering an email
         * that became registered while this verification
         * request was pending.
         */
        if (userRepository.existsByEmailIgnoreCase(verification.getEmail())) {
            throw new EmailAlreadyRegisteredException("Email already registered");
        }

        Role userRole = roleRepository.findByName(DEFAULT_ROLE)
                .orElseThrow(() -> new IllegalStateException("Default USER role is not configured"));

        User user = new User();
        user.setEmail(verification.getEmail());
        user.setPasswordHash(verification.getPasswordHash());
        user.setFirstName(verification.getName());
        user.setLastName(verification.getName());
        user.setEnabled(true);
        user.setAccountNonExpired(true);
        user.setCredentialsNonExpired(true);
        user.setCreatedAt(OffsetDateTime.now());
        user.setUpdatedAt(OffsetDateTime.now());
        user.getRoles().add(userRole);

//        User savedUser = userRepository.save(user);
        /*
         * The User is created ONLY here.
         *
         * Therefore:
         *
         * User exists
         *      =>
         * email was successfully verified.
         */
        userRepository.save(user);

        /*
         * Delete the verification record in the
         * SAME PostgreSQL transaction.
         */
        emailVerificationRepository.delete(verification);
    }

    private String buildVerificationUrl(String rawToken) {

        return "http://localhost:4200"
                + "/verify-email?token="
                + URLEncoder.encode(
                rawToken,
                StandardCharsets.UTF_8);
    }

}