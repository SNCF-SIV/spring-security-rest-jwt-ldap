package com.sncf.siv.poc.security.exceptions;


public class JwtExpirationException extends RuntimeException {
    public JwtExpirationException(String message) {
        super(message);
    }
}
