package com.anodiam.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;

import java.text.ParseException;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

public class AnodiamJwtDecoder implements JwtDecoder {
    private final String jwtSecret;

    public AnodiamJwtDecoder(String jwtSecret) {
        this.jwtSecret = jwtSecret;
    }

    public Jwt decode(String token) throws JwtException {
        JWT jwt = null;
        try {
            jwt = JWTParser.parse(token);
            if (jwt instanceof SignedJWT) {
                SignedJWT signedJWT = (SignedJWT)jwt;
                if(!signedJWT.verify(new MACVerifier(jwtSecret))) {
                    throw new JwtValidationException("Invalid token", Collections.singletonList(new OAuth2Error("INVALID_TOKEN")));
                }
            } else {
                throw new JwtValidationException("Invalid token", Collections.singletonList(new OAuth2Error("INVALID_TOKEN")));
            }
        } catch (ParseException | JOSEException e) {
            throw new RuntimeException(e);
        }
        return createJwt(token, jwt);
    }

    private Jwt createJwt(String token, JWT parsedJwt) {
        try {
            Map<String, Object> headers = new LinkedHashMap<>(parsedJwt.getHeader().toJSONObject());
            Map<String, Object> claims = new LinkedHashMap<>();
            claims.putAll(parsedJwt.getJWTClaimsSet().getClaims());
            claims.put("iat", ((Date)claims.get("iat")).toInstant());
            claims.put("exp", ((Date)claims.get("exp")).toInstant());
            return Jwt.withTokenValue(token)
                    .headers(h -> h.putAll(headers))
                    .claims(c -> c.putAll(claims))
                    .build();
        } catch (Exception ex) {
            if (ex.getCause() instanceof ParseException) {
                throw new JwtException("Malformed payload");
            } else {
                throw new JwtException(ex.getMessage(), ex);
            }
        }
    }
}
