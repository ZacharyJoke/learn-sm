package com.gmcrypto.suite.common;

public class GmCryptoException extends RuntimeException {

    private final ErrorCode errorCode;

    public GmCryptoException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public GmCryptoException(ErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }
}
