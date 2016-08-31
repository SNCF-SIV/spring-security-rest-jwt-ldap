package com.sncf.siv.poc.security.exceptions;


public class MalformedJwtException extends RuntimeException {
    public MalformedJwtException(String message) {
        super(message);
    }
}
