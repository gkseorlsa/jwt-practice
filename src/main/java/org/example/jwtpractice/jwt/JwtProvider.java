package org.example.jwtpractice.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtProvider {

    private final SecretKey key;
    private final long accessTokenValidityMs;

    public JwtProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-token-validity.ms}") long accessTokenValidityMs
    ) {
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
        this.accessTokenValidityMs = accessTokenValidityMs;
    }

    public String createAccessToken(String username, String role) {
        Date now = new Date();

        // subject: 보통 사용자 식별자이다. username 또는 id이다.
        // claim: 권한 같은 추가 정보가 담긴다.
        //      단, 토큰은 누구나 디코딩해서 볼 수 있으니 비밀번호 같은 민감 정보는 넣지 않는다.
        // signWith: 암호화가 아니라 위변조 방지가 목적이다.
        return Jwts.builder()
                .subject(username)
                .claim("role", role)
                .issuedAt(now)
                .expiration(new Date(now.getTime() + accessTokenValidityMs))
                .signWith(key)
                .compact();
    }

    // parseSignedClaims는 서명이 틀리거나 만료됐으면 예외를 던지게 한다.
    // 단순 디코드만 수행하는 것이 아니다. 디코드는 jwt.io 에서 봤듯이, 키 없이 누구나 할 수 있다.
    // 이 메서드는 서명을 우리 키로 다시 계산해서 비교(위변조 검증)하고, 만료 시간 검사 후 payload를 꺼내준다.
    // 통과하지 못 하면 예외를 던진다.
    public Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean validate(String token) {
        try {
            parseClaims(token);
            return true;

        } catch(JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}
