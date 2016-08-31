package com.sncf.siv.poc.security.exceptions;


public class JwtBadSignatureException extends RuntimeException {
    public JwtBadSignatureException(String message) {
        super(message);
    }
}
