package org.nexthope.springsecurity_jwt_auth.authentication;

public record RegisterRequest(String firstname, String lastname, String email, String password) {
}
