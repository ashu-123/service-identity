package com.common.identity.jwt;

import com.common.identity.security.UserPrincipal;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final RSAPrivateKey privateKey;
    private final JwtProperties jwtProperties;

    public String generateAccessToken(UserPrincipal principal) {

        Instant issuedAt = Instant.now();

        Instant expiresAt = issuedAt.plus(jwtProperties.getAccessTokenExpiration());

        List<String> roles = principal.getAuthorities()
                .stream()
                .map(authority -> authority.getAuthority().replaceFirst("^ROLE_", ""))
                .toList();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(principal.getId().toString())
                .issuer(jwtProperties.getIssuer())
                .issueTime(Date.from(issuedAt))
                .expirationTime(Date.from(expiresAt))
                .claim("email", principal.getEmail())
                .claim("roles", roles)
                .build();

        try {
            JWSSigner signer = new RSASSASigner(privateKey);

            SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).build(), claims);

            signedJWT.sign(signer);

            return signedJWT.serialize();

        } catch (JOSEException exception) {
            throw new IllegalStateException("Failed to generate access token", exception);
        }
    }

    public long getAccessTokenExpirationSeconds() {
        return jwtProperties
                .getAccessTokenExpiration()
                .toSeconds();
    }
}
