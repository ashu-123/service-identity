package com.common.identity.exception;

import com.common.identity.exception.model.ApiErrorResponseDto;
import jakarta.servlet.http.HttpServletRequest;

import lombok.extern.slf4j.Slf4j;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ApiErrorResponseDto> handleApiException(ApiException exception, HttpServletRequest request) {

        HttpStatus status = resolveHttpStatus(exception.getErrorCode());
        var response = buildErrorResponse(status, exception.getErrorCode(), exception.getMessage(), request);

        return ResponseEntity.status(status).body(response);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiErrorResponseDto> handleValidationException(MethodArgumentNotValidException exception,
                                                                         HttpServletRequest request) {
        Map<String, String> errorDetails = new LinkedHashMap<>();
        exception.getBindingResult()
                .getFieldErrors()
                .forEach(error -> errorDetails.put(error.getField(), error.getDefaultMessage()));

        HttpStatus status = HttpStatus.BAD_REQUEST;

        ApiErrorResponseDto response = ApiErrorResponseDto.builder()
                .timestamp(Instant.now())
                .status(status.value())
                .code(ErrorCode.VALIDATION_FAILED.name())
                .message("Request validation failed.")
                .path(request.getRequestURI())
                .requestId(getRequestId(request))
                .errorDetails(errorDetails)
                .build();

        return ResponseEntity.status(status).body(response);
    }


    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ApiErrorResponseDto> handleDataIntegrityViolation(DataIntegrityViolationException exception,
            HttpServletRequest request) {

        log.error("Database constraint violation. requestId={}", getRequestId(request), exception);

        HttpStatus status = HttpStatus.CONFLICT;
        var response = buildErrorResponse(status,
                        ErrorCode.USER_ALREADY_EXISTS,
                        "The requested resource conflicts with existing data.",
                        request);

        return ResponseEntity.status(status).body(response);
    }


    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiErrorResponseDto> handleUnexpectedException(Exception exception, HttpServletRequest request) {

        log.error("Unexpected exception. requestId={}", getRequestId(request), exception);

        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;

        var response = buildErrorResponse(status,
                ErrorCode.INTERNAL_SERVER_ERROR,
                "An unexpected error occurred.",
                request);

        return ResponseEntity.status(status).body(response);
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiErrorResponseDto> handleBadCredentials(BadCredentialsException exception,
                                                                    HttpServletRequest request) {

        log.warn("Authentication failed. requestId={}, path={}", getRequestId(request), request.getRequestURI());

        HttpStatus status = HttpStatus.UNAUTHORIZED;

        var response = buildErrorResponse(status,
                ErrorCode.INVALID_CREDENTIALS,
                "Invalid email or password.",
                request);

        return ResponseEntity.status(status).body(response);
    }

    private ApiErrorResponseDto buildErrorResponse(HttpStatus status, ErrorCode errorCode, String message, HttpServletRequest request) {

        return ApiErrorResponseDto.builder()
                .timestamp(Instant.now())
                .status(status.value())
                .code(errorCode.name())
                .message(message)
                .path(request.getRequestURI())
                .requestId(getRequestId(request))
                .build();
    }


    private String getRequestId(HttpServletRequest request) {return request.getHeader("X-Request-Id"); }


    private HttpStatus resolveHttpStatus(ErrorCode errorCode) {

        return switch (errorCode) {
            case USER_ALREADY_EXISTS -> HttpStatus.CONFLICT;
            case USER_NOT_FOUND -> HttpStatus.NOT_FOUND;
            case INVALID_CREDENTIALS -> HttpStatus.UNAUTHORIZED;
            case INVALID_API_VERSION, VALIDATION_FAILED -> HttpStatus.BAD_REQUEST;
            case UNSUPPORTED_API_VERSION -> HttpStatus.NOT_ACCEPTABLE;
            case UNAUTHORIZED -> HttpStatus.UNAUTHORIZED;
            case FORBIDDEN -> HttpStatus.FORBIDDEN;
            case INVALID_TOKEN -> HttpStatus.UNAUTHORIZED;
            case INTERNAL_SERVER_ERROR -> HttpStatus.INTERNAL_SERVER_ERROR;
            default -> HttpStatus.INTERNAL_SERVER_ERROR;
        };
    }
}