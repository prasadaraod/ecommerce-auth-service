package com.ecommerce.auth.config;

import com.ecommerce.auth.model.Role;
import com.ecommerce.auth.model.User;
import com.ecommerce.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        if (!userRepository.existsByEmail("admin@ecommerce.com")) {
            User admin = new User(
                    "Administrator",
                    "admin@ecommerce.com",
                    passwordEncoder.encode("Admin@12345"),
                    Role.ADMIN
            );
            userRepository.save(admin);
        }
    }
}