package com.common.identity.exception.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Getter;

import java.time.Instant;
import java.util.Map;

@Getter
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiErrorResponseDto {

    private final Instant timestamp;

    private final int status;

    private final String code;

    private final String message;

    private final String path;

    private final String requestId;

    private final Map<String, String> errorDetails;
}
