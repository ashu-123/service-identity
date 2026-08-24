package com.common.identity.exception;

public class InvalidOAuthExchangeCodeException extends ApiException {


    public InvalidOAuthExchangeCodeException(String message) {
        super(ErrorCode.INVALID_EXCHANGE_CODE, message);
    }
}
