package org.example.jwtpractice.jwt;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class JwtProviderTest {

    @Autowired JwtProvider jwtProvider;

    @Test
    void 토큰_생성_및_파싱() {
        String token = jwtProvider.createAccessToken("minsu", "ROLE_USER");
        System.out.println(token);

        assertTrue(jwtProvider.validate(token));
        assertEquals("minsu", jwtProvider.parseClaims(token).getSubject());
    }
}