package com.common.identity.auth.model.dto;

public record PasswordResetRequestedEventDto(String email, String resetUrl) { }