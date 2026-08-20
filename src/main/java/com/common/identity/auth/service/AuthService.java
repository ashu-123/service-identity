package com.common.identity.auth.service;


import com.common.identity.auth.model.dto.*;
import com.common.identity.auth.repository.RefreshTokenRepository;
import com.common.identity.exception.UserAlreadyExistException;
import com.common.identity.exception.UserNotFoundException;
import com.common.identity.jwt.JwtService;
import com.common.identity.role.model.entity.Role;
import com.common.identity.role.repository.RoleRepository;
import com.common.identity.security.TokenHashingService;
import com.common.identity.user.model.entity.User;
import com.common.identity.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;

@Service
@RequiredArgsConstructor
public class AuthService {

    private static final String DEFAULT_ROLE = "USER";

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final TokenHashingService tokenHashingService;
    private final RefreshTokenRepository refreshTokenRepository;

    @Transactional
    public SignUpResponseDto signup(SignUpRequestDto request) {

        String normalizedEmail = normalizeEmail(request.getEmail());

        if (userRepository.existsByEmailIgnoreCase(normalizedEmail)) {
            throw new UserAlreadyExistException("An account with this email already exists.");
        }

        Role userRole = roleRepository.findByName(DEFAULT_ROLE)
                .orElseThrow(() -> new IllegalStateException("Default USER role is not configured"));

        OffsetDateTime now = OffsetDateTime.now();

        User user = User.builder()
                .email(normalizedEmail)
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName().trim())
                .lastName(request.getLastName().trim())
                .enabled(true)
                .accountNonLocked(true)
                .accountNonExpired(true)
                .credentialsNonExpired(true)
                .createdAt(now)
                .updatedAt(now)
                .build();

        user.getRoles().add(userRole);

        User savedUser = userRepository.save(user);

        return SignUpResponseDto.builder()
                .id(savedUser.getId())
                .email(savedUser.getEmail())
                .firstName(savedUser.getFirstName())
                .lastName(savedUser.getLastName())
                .message("User registered successfully")
                .build();
    }

//    @Transactional(readOnly = true)
    @Transactional
    public LoginResultDto login(LoginRequestDto request) {

        String normalizedEmail = normalizeEmail(request.getEmail());
        var authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(normalizedEmail, request.getPassword()));

        var principal = (com.common.identity.security.UserPrincipal) authentication.getPrincipal();
        String accessToken = jwtService.generateAccessToken(principal);
        var refreshTokenResult = refreshTokenService.create(principal.getId());

        var authResponse =  AuthResponseDto.builder()
                .accessToken(accessToken)
                .tokenType("Bearer")
                .expiresIn(jwtService.getAccessTokenExpirationSeconds())
                .build();

        return new LoginResultDto(authResponse, refreshTokenResult.rawToken());
    }

    @Transactional(readOnly = true)
    public MeResponseDto getCurrentUser(Long userId) {

        User user = userRepository.findById(userId).orElseThrow(() -> new UserNotFoundException("User does not exist."));
        return MeResponseDto.builder()
                .id(user.getId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .roles(user.getRoles()
                        .stream()
                        .map(Role::getName)
                        .toList())
                .build();
    }

    @Transactional
    public void logout(String rawRefreshToken) {

        if (rawRefreshToken == null || rawRefreshToken.isBlank()) { return; }
        String tokenHash = tokenHashingService.hash(rawRefreshToken);
        refreshTokenRepository.findByTokenHash(tokenHash)
                .ifPresent(token -> refreshTokenService.revokeFamily(token.getFamilyId()));
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase();
    }
}
