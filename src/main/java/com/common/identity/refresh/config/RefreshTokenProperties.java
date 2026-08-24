package com.common.identity.refresh.config;

import lombok.Getter;
import lombok.Setter;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@Getter
@Setter
@ConfigurationProperties(prefix = "auth.refresh-token")
public class RefreshTokenProperties {

    private Duration expiration = Duration.ofDays(30);

    private String cookieName = "refresh_token";

    private String cookiePath = "/api/auth";

    private boolean secure = true;

    private String sameSite = "Lax";
}