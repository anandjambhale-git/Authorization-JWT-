package com.auth.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.UUID;

@Component
public class JwtUtil {
    private final Key key;
    private final long expiryMillis;

    public JwtUtil(
            @Value("${jwt.secret}") String key,
            @Value("${jwt.expiry.in.minutes}") long expiryMinutes) {
        this.key = Keys.hmacShaKeyFor(key.getBytes());
        this.expiryMillis = expiryMinutes * 60* 1000;
    }

    public String generateToken(String username) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setSubject(username)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + expiryMillis))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String validateToken(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject();
        } catch (Exception e) {
            // Token is invalid or expired
            return null;
        }
    }
}
