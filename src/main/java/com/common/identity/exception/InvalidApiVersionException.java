package com.common.identity.exception;

public class InvalidApiVersionException extends ApiException {

    public InvalidApiVersionException(String message) {
        super(ErrorCode.INVALID_API_VERSION, message);
    }
}