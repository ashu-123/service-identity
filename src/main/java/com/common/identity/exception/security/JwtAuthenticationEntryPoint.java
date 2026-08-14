package com.common.identity.exception.security;

// Correct imports for Jackson 3

import com.common.identity.exception.ErrorCode;
import com.common.identity.exception.model.ApiErrorResponseDto;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.time.Instant;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {

        String requestId = request.getHeader("X-Request-Id");

        log.warn("Authentication failed. requestId={}, path={}, reason={}", requestId, request.getRequestURI(), authException.getMessage());

        ApiErrorResponseDto errorResponse = ApiErrorResponseDto.builder()
                .timestamp(Instant.now())
                .status(HttpServletResponse.SC_UNAUTHORIZED)
                .code(ErrorCode.UNAUTHORIZED.name())
                .message("Authentication is required to access this resource.")
                .path(request.getRequestURI())
                .requestId(requestId)
                .build();

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getOutputStream(), errorResponse);
    }
}
