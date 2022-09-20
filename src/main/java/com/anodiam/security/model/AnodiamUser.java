package com.anodiam.security.model;

import org.springframework.security.core.GrantedAuthority;

import java.util.List;

public class AnodiamUser {
    private String name;
    private String givenName;
    private String familyName;
    private String email;
    private String picture;
    private AccessToken token;
    private List<GrantedAuthority> authorities;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getGivenName() {
        return givenName;
    }

    public void setGivenName(String givenName) {
        this.givenName = givenName;
    }

    public String getFamilyName() {
        return familyName;
    }

    public void setFamilyName(String familyName) {
        this.familyName = familyName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPicture() {
        return picture;
    }

    public void setPicture(String picture) {
        this.picture = picture;
    }

    public AccessToken getToken() {
        return token;
    }

    public void setToken(AccessToken token) {
        this.token = token;
    }

    public List<GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(List<GrantedAuthority> authorities) {
        this.authorities = authorities;
    }

    private boolean hasAuthority(String authority) {
        return this.authorities.contains(authority);
    }
}
