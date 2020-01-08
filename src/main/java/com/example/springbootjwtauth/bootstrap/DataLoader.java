package com.example.springbootjwtauth.bootstrap;

import com.example.springbootjwtauth.entity.User;
import com.example.springbootjwtauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class DataLoader implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {

        log.info("Loading users to the database...");

        User user = new User();
        user.setEmail("test@test.com");
        user.setPassword(passwordEncoder.encode("test"));

        userRepository.saveAndFlush(user);

        log.info("Finished loading users.");

    }

}
