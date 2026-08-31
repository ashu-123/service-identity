package com.common.identity.exception;

public class InvalidPasswordResetTokenException extends ApiException {

    public InvalidPasswordResetTokenException() {
        super(ErrorCode.INVALID_PASSWORD_RESET_TOKEN, "Password reset token is invalid or expired");
    }
}