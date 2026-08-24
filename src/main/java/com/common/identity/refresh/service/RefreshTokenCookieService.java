package com.common.identity.refresh.service;

import com.common.identity.refresh.config.RefreshTokenProperties;
import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
@RequiredArgsConstructor
public class RefreshTokenCookieService {

    private final RefreshTokenProperties properties;

    public ResponseCookie create(String refreshToken) {

        return ResponseCookie.from(properties.getCookieName(), refreshToken)
                .httpOnly(true)
//                .secure(properties.isSecure())
                .sameSite(properties.getSameSite())
                .path(properties.getCookiePath())
                .maxAge(properties.getExpiration())
                .build();
    }

    public ResponseCookie clear() {

        return ResponseCookie.from(properties.getCookieName(), "")
                .httpOnly(true)
//                .secure(properties.isSecure())
                .sameSite(properties.getSameSite())
                .path(properties.getCookiePath())
                .maxAge(Duration.ZERO)
                .build();
    }
}