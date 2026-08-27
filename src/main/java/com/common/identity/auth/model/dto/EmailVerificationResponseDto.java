package com.common.identity.auth.model.dto;

public record EmailVerificationResponseDto(boolean verified, String message) { }