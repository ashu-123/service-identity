package com.common.identity.oauth.service;

import com.common.identity.oauth.config.OAuth2Properties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final OAuth2Properties oauth2Properties;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {

        log.warn("Google OAuth2 authentication failed: {}", exception.getClass().getSimpleName());
        String redirectUri = UriComponentsBuilder.fromUriString(oauth2Properties.getFrontendCallbackUri())
                .queryParam("error", "GOOGLE_AUTHENTICATION_FAILED")
                .build()
                .encode()
                .toUriString();

        response.sendRedirect(redirectUri);
    }
}