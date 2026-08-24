package com.common.identity.oauth.model.dto;

public record OAuthExchangeCodeDto(String userId, String accessToken, long expiresIn) { }