package com.common.identity.oauth.model.dto;

import jakarta.validation.constraints.NotBlank;

public record OAuthExchangeRequestDto(@NotBlank String code) { }