package com.common.identity.oauth.config;

import lombok.Getter;
import lombok.Setter;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "oauth2")
@Getter
@Setter
public class OAuth2Properties {

    private String frontendCallbackUri;
    private Duration exchangeCodeExpiration = Duration.ofSeconds(60);
}