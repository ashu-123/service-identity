package com.common.identity.auth.controller;

import com.common.identity.auth.model.dto.*;
import com.common.identity.auth.service.AuthService;
import com.common.identity.refresh.service.RefreshService;
import com.common.identity.refresh.service.RefreshTokenCookieService;
import com.common.identity.oauth.model.dto.OAuthExchangeRequestDto;
import com.common.identity.oauth.service.OAuthAuthorizationCodeService;
import jakarta.validation.Valid;

import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
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

    private final RefreshTokenCookieService refreshTokenCookieService;

    private final RefreshService refreshService;

    private final OAuthAuthorizationCodeService oAuthAuthorizationCodeService;

    @PostMapping(value = "/signup", headers = "Api-Version=1")
    public ResponseEntity<SignUpResponseDto> signup(@Valid @RequestBody SignUpRequestDto request) {
        SignUpResponseDto response = authService.signup(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping(value = "/login", headers = "Api-Version=1")
    public ResponseEntity<AuthResponseDto> login(@Valid @RequestBody LoginRequestDto request) {

        LoginResultDto loginResult = authService.login(request);
        ResponseCookie refreshCookie = refreshTokenCookieService.create(loginResult.refreshToken());
        return ResponseEntity
                .ok()
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .body(loginResult.authResponse());
    }

    @GetMapping(value = "/me", headers = "Api-Version=1")
    public ResponseEntity<MeResponseDto> getCurrentUser(@AuthenticationPrincipal Jwt jwt) {

        Long userId = Long.parseLong(jwt.getSubject());
        MeResponseDto response = authService.getCurrentUser(userId);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponseDto> refresh(@CookieValue(name = "refresh_token") String refreshToken) {

        var refreshResult = refreshService.refresh(refreshToken);
        var responseCookie = refreshTokenCookieService.create(refreshResult.refreshToken());
        return ResponseEntity
                .ok()
                .header(HttpHeaders.SET_COOKIE, responseCookie.toString())
                .body(refreshResult.authResponseDto());
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@CookieValue(name = "refresh_token", required = false) String refreshToken) {

        authService.logout(refreshToken);
        var clearCookie = refreshTokenCookieService.clear();
        return ResponseEntity
                .noContent()
                .header(HttpHeaders.SET_COOKIE, clearCookie.toString())
                .build();
    }

    @PostMapping("/oauth/exchange")
    public ResponseEntity<AuthResponseDto> exchangeOAuthCode(@Valid @RequestBody OAuthExchangeRequestDto request) {

        var exchangeCode = oAuthAuthorizationCodeService.consume(request.code());
        var response = AuthResponseDto.builder()
                .accessToken(exchangeCode.accessToken())
                .tokenType("Bearer")
                .expiresIn(exchangeCode.expiresIn())
                .build();

        return ResponseEntity.ok(response);
    }
}