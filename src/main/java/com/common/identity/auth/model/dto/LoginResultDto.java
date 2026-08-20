package com.common.identity.auth.model.dto;

public record LoginResultDto(AuthResponseDto authResponse, String refreshToken) { }