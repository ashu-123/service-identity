package com.common.identity.exception;

public class PasswordResetNotAllowedException extends ApiException {

    public PasswordResetNotAllowedException() {
        super(ErrorCode.PASSWORD_RESET_NOT_ALLOWED, "Password reset is not available for this account");
    }
}