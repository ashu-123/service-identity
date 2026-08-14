package com.common.identity.exception;

public class UnsupportedApiVersionException extends ApiException {

    public UnsupportedApiVersionException(String message) {
        super(ErrorCode.UNSUPPORTED_API_VERSION, message);
    }
}
