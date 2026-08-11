package com.common.identity.auth.model.dto;

import lombok.Builder;
import lombok.Getter;

import java.util.List;

@Getter
@Builder
public class MeResponseDto {

    private Long id;

    private String email;

    private String firstName;

    private String lastName;

    private List<String> roles;
}
