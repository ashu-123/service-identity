package com.common.identity.exception;

public class UserAlreadyExistException extends ApiException {

    public UserAlreadyExistException(String message) {
        super(ErrorCode.USER_ALREADY_EXISTS, message);
    }
}