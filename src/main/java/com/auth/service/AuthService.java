package com.auth.service;

import com.auth.dto.LoginRequest;
import com.auth.dto.LoginResponse;
import com.auth.entity.UserEntity;
import com.auth.repository.UserRepository;
import com.auth.util.JwtUtil;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();

    public AuthService(UserRepository userRepository, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
    }

    public LoginResponse signup(LoginRequest loginRequest) {
        if (userRepository.existsById(loginRequest.getUsername())){
            return LoginResponse.builder()
                    .message("Username already exists")
                    .build();
        }

        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(loginRequest.getUsername());
        userEntity.setPassword(bCryptPasswordEncoder.encode(loginRequest.getPassword()));

        userRepository.save(userEntity);

        return LoginResponse.builder().message("User registered successfully").build();
    }

    public LoginResponse login(LoginRequest loginRequest) {
        UserEntity userEntity = userRepository.findById(loginRequest.getUsername()).orElse(null);
        if (userEntity == null || !bCryptPasswordEncoder.matches(loginRequest.getPassword(), userEntity.getPassword())) {
            return LoginResponse.builder()
                    .message("Invalid username or password")
                    .build();
        }

        String token = jwtUtil.generateToken(userEntity.getUsername());
        return LoginResponse.builder()
                .message("Login successful")
                .token(token)
                .build();
    }

    public LoginResponse logout(String username) {
        // In a real application, you might want to invalidate the token or manage a token blacklist.
        return LoginResponse.builder()
                .message("User logged out successfully")
                .build();
    }
}
