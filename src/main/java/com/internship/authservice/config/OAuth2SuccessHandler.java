package com.internship.authservice.config;

import com.internship.authservice.entity.User;
import com.internship.authservice.service.AuthService;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final AuthService authService;

    @Value("${app.frontend.url}")
    private String frontendUrl;

    public OAuth2SuccessHandler(AuthService authService) {
        this.authService = authService;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication)
            throws IOException, ServletException {

        OAuth2AuthenticationToken oauthToken =
                (OAuth2AuthenticationToken) authentication;

        OAuth2User oauthUser =
                oauthToken.getPrincipal();

        // =================================================
        // GOOGLE INFORMATION
        // =================================================

        String googleId =
                oauthUser.getAttribute("sub");

        String email =
                oauthUser.getAttribute("email");

        String name =
                oauthUser.getAttribute("name");

        if (googleId == null || email == null) {
            response.sendError(
                    HttpServletResponse.SC_BAD_REQUEST,
                    "Google account information missing"
            );
            return;
        }

        // =================================================
        // FIND / CREATE USER
        // =================================================

        User user =
                authService.findOrCreateGoogleUser(
                        googleId,
                        email,
                        name
                );

        // =================================================
        // GENERATE OUR JWT
        // =================================================

        String token =
                authService.createTokenForUser(user);

        // =================================================
        // REDIRECT TO DEPLOYED FRONTEND
        // =================================================

        response.sendRedirect(
                frontendUrl + "/?token=" + token
        );
    }
}