package com.common.identity.exception;

public class AccountLinkRequiredException extends ApiException {

    public AccountLinkRequiredException( String message) {
        super(ErrorCode.ACC_LINKED_ERROR, message);
    }
}
