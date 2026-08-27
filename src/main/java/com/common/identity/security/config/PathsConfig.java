package com.common.identity.security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;
import java.util.List;

@Configuration
@ConfigurationProperties
public class PathsConfig {

    @Bean(name = "publicPaths")
    public List<String> getPublicPaths() {
        return List.of("/api/auth/signup",
                "/api/auth/login",
                "/api/auth/refresh",
                "/api/auth/email-verification/verify",
                "/api/auth/logout",
                "/actuator/health");
    }

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

}
