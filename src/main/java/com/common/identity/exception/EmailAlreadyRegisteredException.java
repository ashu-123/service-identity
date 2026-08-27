package com.common.identity.exception;

public class EmailAlreadyRegisteredException extends ApiException{

    public EmailAlreadyRegisteredException(String message) {
        super(ErrorCode.EMAIL_ALREADY_EXISTS, message);
    }
}
