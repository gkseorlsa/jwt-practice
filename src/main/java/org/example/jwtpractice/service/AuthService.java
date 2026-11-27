package org.example.jwtpractice.service;

import org.example.jwtpractice.domain.RefreshToken;
import org.example.jwtpractice.domain.User;
import org.example.jwtpractice.dto.LoginRequest;
import org.example.jwtpractice.dto.RefreshRequest;
import org.example.jwtpractice.dto.SignupRequest;
import org.example.jwtpractice.dto.TokenResponse;
import org.example.jwtpractice.jwt.JwtProvider;
import org.example.jwtpractice.repository.RefreshTokenRepository;
import org.example.jwtpractice.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;

    public AuthService(
            UserRepository userRepository,
            RefreshTokenRepository refreshTokenRepository,
            PasswordEncoder passwordEncoder,
            JwtProvider jwtProvider
    ) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
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

    @Transactional
    public TokenResponse login(LoginRequest req) {
        User user = userRepository.findByUsername(req.username())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                        "아이디 또는 비밀번호가 올바르지 않습니다."));

        if (!passwordEncoder.matches(req.password(), user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "아이디 또는 비밀번호가 다릅니다.");
        }

        return issueTokens(user);
    }

    @Transactional
    public TokenResponse refresh(RefreshRequest req) {
        String token = req.refreshToken();

        if (token == null || !jwtProvider.validateRefreshToken(token)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "유효하지 않은 리프레시 토큰입니다.");
        }

        String username = jwtProvider.parseClaims(token).getSubject();

        RefreshToken stored = refreshTokenRepository.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "로그인 정보가 없습니다."));

        if (!stored.getToken().equals(token)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "이미 사용되었거나 폐기된 토큰입니다.");
        }

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "사용자가 없습니다."));

        return issueTokens(user);
    }

    @Transactional
    public void logout(RefreshRequest req) {
        String token = req.refreshToken();

        if (token != null && jwtProvider.validateRefreshToken(token)) {
            refreshTokenRepository.deleteByUsername(jwtProvider.parseClaims(token).getSubject());
        }
    }

    private TokenResponse issueTokens(User user) {
        String access = jwtProvider.createAccessToken(user.getUsername(), user.getRole());
        String refresh = jwtProvider.createRefreshToken(user.getUsername());

        RefreshToken entity = refreshTokenRepository.findByUsername(user.getUsername())
                .orElseGet(() -> new RefreshToken(user.getUsername(), refresh));

        entity.update(refresh);
        refreshTokenRepository.save(entity);

        return new TokenResponse(access, refresh);
    }
}
