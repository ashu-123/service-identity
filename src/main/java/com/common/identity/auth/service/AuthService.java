package com.common.identity.auth.service;


import com.common.identity.auth.model.dto.*;
import com.common.identity.exception.UserAlreadyExistException;
import com.common.identity.exception.UserNotFoundException;
import com.common.identity.jwt.JwtService;
import com.common.identity.role.model.entity.Role;
import com.common.identity.role.repository.RoleRepository;
import com.common.identity.user.model.entity.User;
import com.common.identity.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
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

    @Transactional(readOnly = true)
    public AuthResponseDto login(LoginRequestDto request) {

        String normalizedEmail = normalizeEmail(request.getEmail());

        Authentication authentication =
                authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(normalizedEmail,
                        request.getPassword()));

        var principal = (com.common.identity.security.UserPrincipal) authentication.getPrincipal();

        String accessToken = jwtService.generateAccessToken(principal);

        return AuthResponseDto.builder()
                .accessToken(accessToken)
                .tokenType("Bearer")
                .expiresIn(jwtService.getAccessTokenExpirationSeconds())
                .build();
    }

    @Transactional(readOnly = true)
    public MeResponseDto getCurrentUser(Long userId) {

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User does not exist."));

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

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase();
    }
}
