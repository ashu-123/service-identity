package com.common.identity.exception;

public class InvalidEmailVerificationTokenException extends ApiException {

    public InvalidEmailVerificationTokenException(String message) {
        super(ErrorCode.INVALID_EMAIL_VERIFICATION_TOKEN, message);
    }
}