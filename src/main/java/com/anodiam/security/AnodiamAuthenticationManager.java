package com.anodiam.security;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;

public class AnodiamAuthenticationManager implements AuthenticationManager {
    private final String jwtSecret;

    public AnodiamAuthenticationManager(String jwtSecret) {
        this.jwtSecret = jwtSecret;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if(authentication instanceof BearerTokenAuthenticationToken) {
            final String token = ((BearerTokenAuthenticationToken) authentication).getToken();
            JwtDecoder jwtDecoder = new AnodiamJwtDecoder(jwtSecret);
            Jwt jwt = jwtDecoder.decode(token);
            return new AnodiamAuthentication(jwt);
        } else {
            throw new BadCredentialsException("Invalid Token .. Expected valid BearerToken");
        }
    }
}
