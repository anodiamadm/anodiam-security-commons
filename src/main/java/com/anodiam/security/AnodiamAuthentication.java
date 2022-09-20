package com.anodiam.security;

import com.anodiam.security.model.AccessToken;
import com.anodiam.security.model.AnodiamUser;
import com.nimbusds.jose.shaded.json.JSONObject;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Map;

public class AnodiamAuthentication extends JwtAuthenticationToken {
    private AnodiamUser principal;

    public AnodiamAuthentication(Jwt jwt) {
        super(jwt);
        this.principal = buildPrincipal(jwt);
        setAuthenticated(true);
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    private AnodiamUser buildPrincipal(final Jwt jwt) {
        Map<String, String> attributes = jwt.getClaim("attributes");
        if(attributes.get("provider").equals("google")) {
            return buildGooglePrincipal(jwt);
        } else if(attributes.get("provider").equals("facebook")) {
            return buildFacebookPrincipal(jwt);
        } else {
            return buildAnodiamPrincipal(jwt);
        }
    }

    private AnodiamUser buildGooglePrincipal(final Jwt jwt) {
        AnodiamUser anodiamUser = new AnodiamUser();
        AccessToken accessToken = new AccessToken();
        accessToken.setValue(jwt.getTokenValue());
        accessToken.setIssuedAt(jwt.getIssuedAt());
        accessToken.setExpiresAt(jwt.getExpiresAt());
        Map<String, String> attributes = jwt.getClaim("attributes");
        anodiamUser.setName(attributes.get("name"));
        anodiamUser.setGivenName(attributes.get("given_name"));
        anodiamUser.setFamilyName(attributes.get("family_name"));
        anodiamUser.setEmail(attributes.get("email"));
        anodiamUser.setPicture(attributes.get("picture"));
        anodiamUser.setToken(accessToken);
        anodiamUser.setAuthorities(jwt.getClaim("authorities"));
        return anodiamUser;
    }

    private AnodiamUser buildFacebookPrincipal(final Jwt jwt) {
        AnodiamUser anodiamUser = new AnodiamUser();
        AccessToken accessToken = new AccessToken();
        accessToken.setValue(jwt.getTokenValue());
        accessToken.setIssuedAt(jwt.getIssuedAt());
        accessToken.setExpiresAt(jwt.getExpiresAt());
        Map<String, Object> attributes = jwt.getClaim("attributes");
        anodiamUser.setName(attributes.get("name").toString());
        anodiamUser.setGivenName(attributes.get("first_name").toString());
        anodiamUser.setFamilyName(attributes.get("last_name").toString());
        anodiamUser.setEmail(attributes.get("email").toString());
        JSONObject picture = (JSONObject) attributes.get("picture");
        JSONObject pictureData = (JSONObject) picture.get("data");
        String url = pictureData.getAsString("url");
        anodiamUser.setPicture(url);
        anodiamUser.setToken(accessToken);
        anodiamUser.setAuthorities(jwt.getClaim("authorities"));
        return anodiamUser;
    }

    private AnodiamUser buildAnodiamPrincipal(final Jwt jwt) {
        AnodiamUser anodiamUser = new AnodiamUser();
        return anodiamUser;
    }
}
