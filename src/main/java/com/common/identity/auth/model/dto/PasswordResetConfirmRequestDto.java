package com.common.identity.auth.model.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PasswordResetConfirmRequestDto(@NotBlank String token,
                                             @NotBlank(message = "Password is required")
                                             @Size(min = 8, max = 100, message = "Password must be between 8 and 100 characters")
                                             String newPassword) { }