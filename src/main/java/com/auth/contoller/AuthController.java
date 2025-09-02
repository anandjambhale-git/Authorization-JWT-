package com.auth.contoller;

import com.auth.dto.LoginRequest;
import com.auth.dto.LoginResponse;
import com.auth.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest) {
        LoginResponse response = authService.login(loginRequest);
        if (response.getToken() == null) {
            return ResponseEntity.status(401).body(response);
        }
        return ResponseEntity.ok(response);
    }

    @PostMapping("/signup")
    public LoginResponse signup(@RequestBody LoginRequest loginRequest) {
        return authService.signup(loginRequest);
    }

    @PostMapping("/logout")
    public LoginResponse logout(String username) {
        return authService.logout(username);
    }

    @PostMapping("/validateToken")
    public ResponseEntity<LoginResponse> checkToken(@RequestHeader(name = "authorization") String token) {
        Optional<String> validateToken = authService.validateToken(token);
        if (validateToken.isPresent()) {
            return ResponseEntity.ok(LoginResponse.builder()
                    .message("Token is valid")
                    .token(token)
                    .build());
        }else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(LoginResponse.builder()
                    .message("Token is invalid or expired")
                    .build());
        }
    }
}
