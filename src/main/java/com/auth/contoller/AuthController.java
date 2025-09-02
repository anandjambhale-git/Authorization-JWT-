package com.auth.contoller;

import com.auth.dto.LoginRequest;
import com.auth.dto.LoginResponse;
import com.auth.service.AuthService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest loginRequest) {
        return authService.login(loginRequest);
    }

    @PostMapping("/signup")
    public LoginResponse signup(@RequestBody LoginRequest loginRequest) {
        return authService.signup(loginRequest);
    }

    @PostMapping("/logout")
    public LoginResponse logout(String username) {
        return authService.logout(username);
    }
}
