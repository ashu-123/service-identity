package com.common.identity.exception;

public class RefreshTokenReplayException extends ApiException {

    public RefreshTokenReplayException() {
        super(ErrorCode.REFRESH_TOKEN_REUSE_DETECTED, "Refresh token is no longer valid.");
    }
}