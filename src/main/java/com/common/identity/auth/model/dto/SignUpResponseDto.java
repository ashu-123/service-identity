package com.common.identity.auth.model.dto;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class SignUpResponseDto {

    private Long id;
    private String email;
    private String firstName;
    private String lastName;
    private String message;
}
