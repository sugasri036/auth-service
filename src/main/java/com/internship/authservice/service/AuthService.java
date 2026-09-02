package com.internship.authservice.service;

import com.internship.authservice.entity.User;
import com.internship.authservice.repository.UserRepository;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;


    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService) {

        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }


    // =====================================================
    // REGISTER USER
    // =====================================================

    public User registerUser(
            String email,
            String password,
            String name) {

        if (email == null ||
                email.isBlank()) {

            throw new IllegalArgumentException(
                    "Email is required"
            );
        }

        if (password == null ||
                password.isBlank()) {

            throw new IllegalArgumentException(
                    "Password is required"
            );
        }

        if (userRepository.existsByEmail(
                email.trim().toLowerCase())) {

            throw new IllegalArgumentException(
                    "Email already registered"
            );
        }

        User user = new User();

        user.setEmail(
                email.trim().toLowerCase()
        );

        user.setPassword(
                passwordEncoder.encode(password)
        );

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

        if (email == null ||
                email.isBlank()) {

            throw new IllegalArgumentException(
                    "Email is required"
            );
        }

        if (password == null ||
                password.isBlank()) {

            throw new IllegalArgumentException(
                    "Password is required"
            );
        }

        User user =
                userRepository
                        .findByEmail(
                                email.trim().toLowerCase()
                        )
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

    public String createTokenForUser(
            User user) {

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

                    User existingUser =
                            userRepository
                                    .findByEmail(email)
                                    .orElse(null);

                    if (existingUser != null) {

                        existingUser.setGoogleId(
                                googleId
                        );

                        existingUser.setProvider(
                                "GOOGLE"
                        );

                        if (existingUser.getName() == null) {

                            existingUser.setName(
                                    name
                            );
                        }

                        return userRepository.save(
                                existingUser
                        );
                    }

                    User user =
                            new User();

                    user.setEmail(email);

                    user.setName(name);

                    user.setGoogleId(
                            googleId
                    );

                    user.setProvider(
                            "GOOGLE"
                    );

                    user.setPassword(null);

                    return userRepository.save(user);
                });
    }
}