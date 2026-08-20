package com.common.identity.exception;

public class InvalidRefreshTokenException extends ApiException {

    public InvalidRefreshTokenException() {
        super(ErrorCode.INVALID_REFRESH_TOKEN, "Invalid refresh token.");
    }
}