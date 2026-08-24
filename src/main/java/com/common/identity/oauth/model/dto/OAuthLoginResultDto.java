package com.common.identity.oauth.model.dto;

import com.common.identity.auth.model.dto.AuthResponseDto;

import java.util.UUID;

public record OAuthLoginResultDto(Long userId, AuthResponseDto authResponse, String refreshToken) { }