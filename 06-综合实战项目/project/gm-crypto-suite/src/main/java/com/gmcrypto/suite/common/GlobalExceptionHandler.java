package com.gmcrypto.suite.common;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(GmCryptoException.class)
    public ResponseEntity<Map<String, String>> handle(GmCryptoException exception) {
        HttpStatus status = switch (exception.getErrorCode()) {
            case KEY_NOT_FOUND, INVALID_PARAMETER -> HttpStatus.BAD_REQUEST;
            default -> HttpStatus.INTERNAL_SERVER_ERROR;
        };
        return ResponseEntity.status(status).body(Map.of(
                "errorCode", exception.getErrorCode().name()));
    }
}
