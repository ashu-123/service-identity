package com.common.identity.auth.model.dto;

public record EmailVerificationRequestDto(String email, String verificationUrl) { }