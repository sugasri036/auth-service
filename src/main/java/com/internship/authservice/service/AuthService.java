package com.internship.authservice.service;

import com.internship.authservice.entity.User;
import com.internship.authservice.repository.UserRepository;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RestTemplate restTemplate;

    @Value("${otp.service.url}")
    private String otpServiceUrl;

    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService,
            RestTemplate restTemplate) {

        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.restTemplate = restTemplate;
    }

    // =====================================================
    // REGISTER USER
    // =====================================================

    public User registerUser(
            String email,
            String password,
            String name) {

        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("Email is required");
        }

        if (password == null || password.isBlank()) {
            throw new IllegalArgumentException("Password is required");
        }

        String normalizedEmail = email.trim().toLowerCase();

        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new IllegalArgumentException("Email already registered");
        }

        User user = new User();

        user.setEmail(normalizedEmail);
        user.setPassword(passwordEncoder.encode(password));
        user.setName(name);
        user.setProvider("LOCAL");

        return userRepository.save(user);
    }

    // =====================================================
    // LOGIN USER
    // =====================================================

    public User loginUser(
            String email,
            String password) {

        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("Email is required");
        }

        if (password == null || password.isBlank()) {
            throw new IllegalArgumentException("Password is required");
        }

        User user = userRepository
                .findByEmail(email.trim().toLowerCase())
                .orElseThrow(
                        () -> new RuntimeException(
                                "Invalid email or password"
                        )
                );

        if (user.getPassword() == null) {
            throw new RuntimeException(
                    "This account uses Google login"
            );
        }

        boolean passwordMatches =
                passwordEncoder.matches(
                        password,
                        user.getPassword()
                );

        if (!passwordMatches) {
            throw new RuntimeException(
                    "Invalid email or password"
            );
        }

        return user;
    }

    // =====================================================
    // CREATE JWT
    // =====================================================

    public String createTokenForUser(User user) {

        return jwtService.generateToken(
                user.getEmail()
        );
    }

    // =====================================================
    // GOOGLE USER
    // =====================================================

    public User findOrCreateGoogleUser(
            String googleId,
            String email,
            String name) {

        return userRepository
                .findByGoogleId(googleId)
                .orElseGet(() -> {

                    String normalizedEmail =
                            email.trim().toLowerCase();

                    User existingUser =
                            userRepository
                                    .findByEmail(normalizedEmail)
                                    .orElse(null);

                    if (existingUser != null) {

                        existingUser.setGoogleId(googleId);
                        existingUser.setProvider("GOOGLE");

                        if (existingUser.getName() == null) {
                            existingUser.setName(name);
                        }

                        return userRepository.save(existingUser);
                    }

                    User user = new User();

                    user.setEmail(normalizedEmail);
                    user.setName(name);
                    user.setGoogleId(googleId);
                    user.setProvider("GOOGLE");
                    user.setPassword(null);

                    return userRepository.save(user);
                });
    }

    // =====================================================
    // FORGOT PASSWORD - SEND OTP
    // =====================================================

    public void sendForgotPasswordOtp(String email) {

        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException(
                    "Email is required"
            );
        }

        String normalizedEmail =
                email.trim().toLowerCase();

        User user =
                userRepository
                        .findByEmail(normalizedEmail)
                        .orElseThrow(
                                () -> new RuntimeException(
                                        "No account found with this email"
                                )
                        );

        // Google-only users don't have a local password.
        if (user.getPassword() == null) {
            throw new RuntimeException(
                    "This account uses Google login. Please continue with Google."
            );
        }

        String url =
                otpServiceUrl + "/otp/generate";

        Map<String, String> request =
                Map.of(
                        "identifier",
                        normalizedEmail
                );

        restTemplate.postForEntity(
                url,
                request,
                Map.class
        );
    }

    // =====================================================
    // VERIFY FORGOT PASSWORD OTP
    // =====================================================

    public String verifyForgotPasswordOtp(
            String email,
            String otp) {

        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException(
                    "Email is required"
            );
        }

        if (otp == null || otp.isBlank()) {
            throw new IllegalArgumentException(
                    "OTP is required"
            );
        }

        String normalizedEmail =
                email.trim().toLowerCase();

        User user =
                userRepository
                        .findByEmail(normalizedEmail)
                        .orElseThrow(
                                () -> new RuntimeException(
                                        "No account found with this email"
                                )
                        );

        if (user.getPassword() == null) {
            throw new RuntimeException(
                    "This account uses Google login. Please continue with Google."
            );
        }

        String url =
                otpServiceUrl + "/otp/verify";

        Map<String, String> request =
                Map.of(
                        "identifier",
                        normalizedEmail,
                        "otp",
                        otp.trim()
                );

        var response =
                restTemplate.postForEntity(
                        url,
                        request,
                        Map.class
                );

        if (response.getBody() == null) {
            throw new RuntimeException(
                    "Invalid or expired OTP"
            );
        }

        Object success =
                response.getBody().get("success");

        if (!(success instanceof Boolean)
                || !((Boolean) success)) {

            throw new RuntimeException(
                    "Invalid or expired OTP"
            );
        }

        Object sessionToken =
                response.getBody().get("sessionToken");

        if (sessionToken == null
                || sessionToken.toString().isBlank()) {

            throw new RuntimeException(
                    "Could not create reset session"
            );
        }

        return sessionToken.toString();
    }

    // =====================================================
    // RESET PASSWORD
    // =====================================================

    public void resetPassword(
            String email,
            String sessionToken,
            String newPassword) {

        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException(
                    "Email is required"
            );
        }

        if (sessionToken == null
                || sessionToken.isBlank()) {

            throw new IllegalArgumentException(
                    "Reset session is required"
            );
        }

        if (newPassword == null
                || newPassword.isBlank()) {

            throw new IllegalArgumentException(
                    "New password is required"
            );
        }

        if (newPassword.length() < 6) {
            throw new IllegalArgumentException(
                    "Password must be at least 6 characters"
            );
        }

        String normalizedEmail =
                email.trim().toLowerCase();

        User user =
                userRepository
                        .findByEmail(normalizedEmail)
                        .orElseThrow(
                                () -> new RuntimeException(
                                        "No account found with this email"
                                )
                        );

        if (user.getPassword() == null) {
            throw new RuntimeException(
                    "This account uses Google login. Please continue with Google."
            );
        }

        // -------------------------------------------------
        // Validate OTP reset session
        // -------------------------------------------------

        String sessionUrl =
                otpServiceUrl
                        + "/otp/session/"
                        + sessionToken.trim();

        var sessionResponse =
                restTemplate.getForEntity(
                        sessionUrl,
                        Map.class
                );

        if (sessionResponse.getBody() == null) {
            throw new RuntimeException(
                    "Invalid or expired reset session"
            );
        }

        Object success =
                sessionResponse.getBody().get("success");

        Object identifier =
                sessionResponse.getBody().get("identifier");

        if (!(success instanceof Boolean)
                || !((Boolean) success)
                || identifier == null
                || !normalizedEmail.equals(
                        identifier.toString()
                                .trim()
                                .toLowerCase()
                )) {

            throw new RuntimeException(
                    "Invalid or expired reset session"
            );
        }

        // -------------------------------------------------
        // Update password
        // -------------------------------------------------

        user.setPassword(
                passwordEncoder.encode(newPassword)
        );

        userRepository.save(user);
    }
}