package com.anodiam.security;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.text.ParseException;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

public class AnodiamJwtDecoder implements JwtDecoder {

    public Jwt decode(String token) throws JwtException {
        JWT jwt = null;
        try {
            jwt = JWTParser.parse(token);
        } catch (ParseException e) {
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
