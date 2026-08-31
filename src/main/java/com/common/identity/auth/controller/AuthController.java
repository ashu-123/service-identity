package com.common.identity.auth.controller;

import com.common.identity.auth.model.dto.*;
import com.common.identity.auth.service.AuthService;
import com.common.identity.auth.service.EmailVerificationService;
import com.common.identity.auth.service.PasswordResetService;
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

    private final EmailVerificationService emailVerificationService;

    private final PasswordResetService passwordResetService;

    @PostMapping(value = "/signup", headers = "Api-Version=1")
    public ResponseEntity<String> signup(@Valid @RequestBody SignUpRequestDto request) {

        emailVerificationService.initiateRegistration(request);
//        SignUpResponseDto response = authService.signup(request);
        return ResponseEntity.status(HttpStatus.OK).body("Email registration started");
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

    @GetMapping("/email-verification/verify")
    public ResponseEntity<EmailVerificationResponseDto>
    verifyEmail(
            @RequestParam String token
    ) {

        emailVerificationService.verifyEmail(
                token
        );

        return ResponseEntity.ok(
                new EmailVerificationResponseDto(
                        true,
                        "Email verified successfully."
                )
        );
    }

    @PostMapping(value = "/password-reset/request")
    public ResponseEntity<PasswordResetResponseDto> requestPasswordReset(@Valid @RequestBody PasswordResetRequestDto request) {

        passwordResetService.requestPasswordReset(request.email());
        return ResponseEntity.ok(new PasswordResetResponseDto("""
                If an account exists for this email,
                a password reset link has been sent."""));
    }

    @PostMapping(value = "/password-reset/confirm")
    public ResponseEntity<PasswordResetConfirmationResponseDto> confirmPasswordReset(@Valid @RequestBody PasswordResetConfirmRequestDto request) {

        passwordResetService.resetPassword(request);
        return ResponseEntity.ok(new PasswordResetConfirmationResponseDto("Password reset successfully."));
    }
}