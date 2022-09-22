package com.anodiam.security.autoconfigure;

import com.anodiam.security.AnodiamAuthenticationManager;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@EnableGlobalMethodSecurity(
        securedEnabled = true,
        jsr250Enabled = true,
        prePostEnabled = true
)
@ConditionalOnProperty(name = "anodiam.security.enabled", havingValue = "true", matchIfMissing = true)
public class SecurityConfig {

    @Value("${spring.security.anodiam.jwt.secret:INVALID_KEY}")
    private String jwtSecret;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // All routes require authentication
        http.authorizeRequests().anyRequest().authenticated();

        // JWT token validation is used
        http.oauth2ResourceServer().jwt(jwt -> {
            jwt.authenticationManager(new AnodiamAuthenticationManager(jwtSecret));
        });

        return http.build();
    }

}
