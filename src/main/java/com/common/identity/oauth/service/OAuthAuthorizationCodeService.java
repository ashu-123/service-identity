package com.common.identity.oauth.service;

import com.common.identity.exception.InvalidOAuthExchangeCodeException;
import com.common.identity.oauth.model.dto.OAuthExchangeCodeDto;
import com.common.identity.oauth.utils.OAuthExchangeCodeGenerator;
import com.common.identity.security.TokenHashingService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.LinkedHashMap;

@Service
@RequiredArgsConstructor
public class OAuthAuthorizationCodeService {

    private static final Duration CODE_TTL = Duration.ofSeconds(60);
    private static final String KEY_PREFIX = "oauth:exchange:";
    private final RedisTemplate<String, Object> redisTemplate;
    private final OAuthExchangeCodeGenerator codeGenerator;
    private final TokenHashingService tokenHashingService;

    public String create(Long userId, String accessToken, long expiresIn) {

        String rawCode = codeGenerator.generate();
        String codeHash = tokenHashingService.hash(rawCode);
        String key = KEY_PREFIX + codeHash;
        var exchangeCode = new OAuthExchangeCodeDto(userId.toString(), accessToken, expiresIn);

        redisTemplate.opsForValue().set(key, exchangeCode, CODE_TTL);
        return rawCode;
    }

    public OAuthExchangeCodeDto consume(String rawCode) {

        String codeHash = tokenHashingService.hash(rawCode);
        String key = KEY_PREFIX + codeHash;
        Object value = redisTemplate.opsForValue().getAndDelete(key);

        if (value == null) {
            throw new InvalidOAuthExchangeCodeException("Invalid Exchange Code");
        }

        LinkedHashMap<String, ?> redisVal = (LinkedHashMap<String, String>) value;
        String userId = (String) redisVal.get("userId");
        String accessToken = (String) redisVal.get("accessToken");
        var expiresIn = (Integer) redisVal.get("expiresIn");

        return new OAuthExchangeCodeDto(userId, accessToken, Long.valueOf(expiresIn));
    }
}