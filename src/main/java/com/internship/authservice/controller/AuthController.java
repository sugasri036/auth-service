package com.internship.authservice.controller;

import com.internship.authservice.entity.User;
import com.internship.authservice.service.AuthService;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    // =====================================================
    // REGISTER
    // =====================================================

    @PostMapping("/register")
    public ResponseEntity<?> register(
            @RequestBody Map<String, String> request) {

        try {

            String email = request.get("email");
            String password = request.get("password");
            String name = request.get("name");

            User user =
                    authService.registerUser(
                            email,
                            password,
                            name
                    );

            String token =
                    authService.createTokenForUser(user);

            return ResponseEntity.ok(
                    Map.of(
                            "message",
                            "Registration successful",

                            "token",
                            token,

                            "user",
                            Map.of(
                                    "id", user.getId(),
                                    "name", user.getName(),
                                    "email", user.getEmail()
                            )
                    )
            );

        } catch (Exception e) {

            return ResponseEntity
                    .badRequest()
                    .body(
                            Map.of(
                                    "error",
                                    e.getMessage()
                            )
                    );
        }
    }

    // =====================================================
    // LOGIN
    // =====================================================

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody Map<String, String> request) {

        try {

            String email = request.get("email");
            String password = request.get("password");

            User user =
                    authService.loginUser(
                            email,
                            password
                    );

            String token =
                    authService.createTokenForUser(user);

            return ResponseEntity.ok(
                    Map.of(
                            "message",
                            "Login successful",

                            "token",
                            token,

                            "user",
                            Map.of(
                                    "id", user.getId(),
                                    "name", user.getName(),
                                    "email", user.getEmail()
                            )
                    )
            );

        } catch (Exception e) {

            return ResponseEntity
                    .badRequest()
                    .body(
                            Map.of(
                                    "error",
                                    e.getMessage()
                            )
                    );
        }
    }

    // =====================================================
    // FORGOT PASSWORD - SEND OTP
    // =====================================================

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(
            @RequestBody Map<String, String> request) {

        try {

            String email =
                    request.get("email");

            authService.sendForgotPasswordOtp(email);

            return ResponseEntity.ok(
                    Map.of(
                            "success",
                            true,

                            "message",
                            "OTP sent successfully"
                    )
            );

        } catch (Exception e) {

            return ResponseEntity
                    .badRequest()
                    .body(
                            Map.of(
                                    "success",
                                    false,

                                    "message",
                                    e.getMessage()
                            )
                    );
        }
    }

    // =====================================================
    // VERIFY FORGOT PASSWORD OTP
    // =====================================================

    @PostMapping("/forgot-password/verify")
    public ResponseEntity<?> verifyForgotPasswordOtp(
            @RequestBody Map<String, String> request) {

        try {

            String email =
                    request.get("email");

            String otp =
                    request.get("otp");

            String sessionToken =
                    authService.verifyForgotPasswordOtp(
                            email,
                            otp
                    );

            return ResponseEntity.ok(
                    Map.of(
                            "success",
                            true,

                            "message",
                            "OTP verified successfully",

                            "sessionToken",
                            sessionToken
                    )
            );

        } catch (Exception e) {

            return ResponseEntity
                    .badRequest()
                    .body(
                            Map.of(
                                    "success",
                                    false,

                                    "message",
                                    e.getMessage()
                            )
                    );
        }
    }

    // =====================================================
    // RESET PASSWORD
    // =====================================================

    @PostMapping("/forgot-password/reset")
    public ResponseEntity<?> resetPassword(
            @RequestBody Map<String, String> request) {

        try {

            String email =
                    request.get("email");

            String sessionToken =
                    request.get("sessionToken");

            String newPassword =
                    request.get("newPassword");

            authService.resetPassword(
                    email,
                    sessionToken,
                    newPassword
            );

            return ResponseEntity.ok(
                    Map.of(
                            "success",
                            true,

                            "message",
                            "Password reset successfully"
                    )
            );

        } catch (Exception e) {

            return ResponseEntity
                    .badRequest()
                    .body(
                            Map.of(
                                    "success",
                                    false,

                                    "message",
                                    e.getMessage()
                            )
                    );
        }
    }

    // =====================================================
    // AUTH SERVICE HEALTH CHECK
    // =====================================================

    @GetMapping("/test")
    public ResponseEntity<?> test() {

        return ResponseEntity.ok(
                Map.of(
                        "message",
                        "Auth Service is working"
                )
        );
    }
}