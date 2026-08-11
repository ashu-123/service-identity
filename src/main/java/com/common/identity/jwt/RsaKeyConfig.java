package com.common.identity.jwt;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class RsaKeyConfig {

    @Bean
    public RSAPrivateKey rsaPrivateKey(@Value("${jwt.private-key-location}") String location) {

        try {
            String pem;
            try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(location)) {
                if (inputStream == null) {
                    throw new IllegalStateException("RSA private key not found: " + location);
                }
                pem = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
            }

            String privateKeyContent = pem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] decoded = Base64.getDecoder().decode(privateKeyContent);

            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);

        } catch (Exception exception) {
            throw new IllegalStateException("Failed to load RSA private key", exception);
        }
    }

    @Bean
    public RSAPublicKey rsaPublicKey(@Value("${jwt.public-key-location}") String location) {
        try {
            String pem = readKey(location);

            String content = pem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] decoded = Base64.getDecoder().decode(content);

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            return (RSAPublicKey) keyFactory.generatePublic(keySpec);

        } catch (Exception exception) {
            throw new IllegalStateException("Failed to load RSA public key", exception);
        }
    }

    private String readKey(String location) {

        try (var inputStream = getClass().getClassLoader().getResourceAsStream(location)) {

            if (inputStream == null) {
                throw new IllegalStateException("RSA key not found: " + location);
            }

            return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);

        } catch (Exception exception) {
            throw new IllegalStateException("Failed to read RSA key: " + location, exception);
        }
    }
}
