package com.cos.jwt.config.jwt;

public interface JwtProperties {
    String SECRET = "cos";
    int EXPIRED_TIME = 60000 * 10;
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
}
