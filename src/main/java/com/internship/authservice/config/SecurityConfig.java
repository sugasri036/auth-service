package com.internship.authservice.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

@Configuration
public class SecurityConfig {

    @Value("${app.frontend.url}")
    private String frontendUrl;

    @Value("${jwt.secret}")
    private String jwtSecret;

    private final OAuth2SuccessHandler oauth2SuccessHandler;

    public SecurityConfig(
            OAuth2SuccessHandler oauth2SuccessHandler) {

        this.oauth2SuccessHandler =
                oauth2SuccessHandler;
    }

    // =====================================================
    // SECURITY FILTER CHAIN
    // =====================================================

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http)
            throws Exception {

        http

                // -------------------------------------------------
                // CSRF
                // -------------------------------------------------

                .csrf(csrf ->
                        csrf.disable()
                )

                // -------------------------------------------------
                // AUTHORIZATION
                // -------------------------------------------------

                .authorizeHttpRequests(auth ->
                        auth

                                // PUBLIC AUTH ENDPOINTS
                                .requestMatchers(
                                        "/api/auth/register",
                                        "/api/auth/login",
                                        "/api/auth/test"
                                )
                                .permitAll()

                                // GOOGLE OAUTH2
                                .requestMatchers(
                                        "/oauth2/**",
                                        "/login/**"
                                )
                                .permitAll()

                                // ACTUATOR
                                .requestMatchers(
                                        "/actuator/health"
                                )
                                .permitAll()

                                // EVERYTHING ELSE
                                .anyRequest()
                                .authenticated()
                )

                // -------------------------------------------------
                // GOOGLE LOGIN
                // -------------------------------------------------

                .oauth2Login(oauth2 ->
                        oauth2
                                .successHandler(
                                        oauth2SuccessHandler
                                )
                )

                // -------------------------------------------------
                // JWT AUTHENTICATION
                // -------------------------------------------------

                .oauth2ResourceServer(oauth2 ->
                      oauth2.jwt(jwt -> {})
                );
            

        return http.build();
    }


    // =====================================================
    // JWT DECODER
    // =====================================================

    @Bean
    public JwtDecoder jwtDecoder() {

        SecretKeySpec secretKey =
                new SecretKeySpec(
                        jwtSecret.getBytes(
                                StandardCharsets.UTF_8
                        ),
                        "HmacSHA256"
                );

        return NimbusJwtDecoder
                .withSecretKey(secretKey)
                .build();
    }
}