package com.common.identity.oauth.service;

import com.common.identity.refresh.service.RefreshTokenCookieService;
import com.common.identity.jwt.JwtService;
import com.common.identity.oauth.model.dto.OAuthLoginResultDto;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

import static java.net.URLEncoder.encode;
import static java.nio.charset.StandardCharsets.UTF_8;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final OAuth2IdentityService oauth2IdentityService;
    private final RefreshTokenCookieService refreshTokenCookieService;
    private final JwtService jwtService;
    private final OAuthAuthorizationCodeService oAuthAuthorizationCodeService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
        OAuthLoginResultDto result = oauth2IdentityService.authenticate(oidcUser);
        ResponseCookie refreshCookie = refreshTokenCookieService.create(result.refreshToken());

        response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());

        // We will discuss the safe redirect below.
        String authorizationCode = oAuthAuthorizationCodeService.create(result.userId(),
                                                                        result.authResponse().getAccessToken(),
                                                                        result.authResponse().getExpiresIn());

        response.sendRedirect("http://localhost:4200/oauth/callback?code=" + encode(authorizationCode, UTF_8));
    }
}