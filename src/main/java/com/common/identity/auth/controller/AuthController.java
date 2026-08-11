package com.common.identity.auth.controller;

import com.common.identity.auth.model.dto.*;
import com.common.identity.auth.service.AuthService;
import jakarta.validation.Valid;

import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

/**
 * The resource Controller class that accepts and processes API requests.
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping(value = "/signup", headers = "Api-Version=1")
    public ResponseEntity<SignUpResponseDto> signup(@Valid @RequestBody SignUpRequestDto request) {
        SignUpResponseDto response = authService.signup(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping(value = "/login", headers = "Api-Version=1")
    public ResponseEntity<AuthResponseDto> login(@Valid @RequestBody LoginRequestDto request) {
        AuthResponseDto response = authService.login(request);

        return ResponseEntity.ok(response);
    }

    @GetMapping(value = "/me", headers = "Api-Version=1")
    public ResponseEntity<MeResponseDto> getCurrentUser(@AuthenticationPrincipal Jwt jwt) {

        Long userId = Long.parseLong(jwt.getSubject());
        MeResponseDto response = authService.getCurrentUser(userId);

        return ResponseEntity.ok(response);
    }
}