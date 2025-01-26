package org.nexthope.springsecurity_jwt_auth.exception;

public class UserFoundException extends RuntimeException {

    public UserFoundException(String message) {
        super(message);
    }

    public UserFoundException(String message, Throwable throwable) {
        super(message, throwable);
    }

}
