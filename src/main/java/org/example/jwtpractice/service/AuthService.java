package org.example.jwtpractice.service;

import org.example.jwtpractice.domain.User;
import org.example.jwtpractice.dto.LoginRequest;
import org.example.jwtpractice.dto.SignupRequest;
import org.example.jwtpractice.dto.TokenResponse;
import org.example.jwtpractice.jwt.JwtProvider;
import org.example.jwtpractice.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;

    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtProvider jwtProvider
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtProvider = jwtProvider;
    }

    public void signup(SignupRequest req) {
        if (userRepository.existsByUsername(req.username())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "이미 존재하는 사용자입니다.");
        }

        String encoded = passwordEncoder.encode(req.password());
        userRepository.save(new User(
                req.username(), encoded, "ROLE_USER"
        ));
    }

    public TokenResponse login(LoginRequest req) {
        User user = userRepository.findByUsername(req.username())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));

        if (!passwordEncoder.matches(req.password(), user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "아이디 또는 비밀번호가 다릅니다.");
        }

        String token = jwtProvider.createAccessToken(user.getUsername(), user.getRole());
        return new TokenResponse(token);
    }
}
