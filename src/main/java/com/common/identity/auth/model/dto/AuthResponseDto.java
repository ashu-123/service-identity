package com.common.identity.auth.model.dto;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class AuthResponseDto {

    private String accessToken;

    private String tokenType;

    private long expiresIn;
}
