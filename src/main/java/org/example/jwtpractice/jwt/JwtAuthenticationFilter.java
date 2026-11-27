package org.example.jwtpractice.jwt;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

// OncePerRequestFilter: 요청 당 딱 한 번만 실행되는 필터 기반 클래스
//      토큰이 없거나 유효하지 않으면 인증 정보 없이 그냥 통과시킨다. 통행을 막진 않는다.
//      단, 뒤의 authorizeHttpRequests가 인증이 안 되었다고 판단해서 거절한다.

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;

    public JwtAuthenticationFilter(JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest req,
            HttpServletResponse res,
            FilterChain filterChain
    ) throws ServletException, IOException {
        String token = resolveToken(req);

        if (token != null && jwtProvider.validate(token)) {
            Claims claims = jwtProvider.parseClaims(token);

            if ("access".equals(claims.get("type", String.class))) {
                String username = claims.getSubject();
                String role = claims.get("role", String.class);


                // UsernamePasswordAuthenticationToken: 세 번째 인자가 인가에서 사용된다.

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                username,
                                null,
                                List.of(new SimpleGrantedAuthority(role))
                        );

                // SecurityContext: 지금 처리 중인 요청의 주인이 누구인지 적어두는 메모장이다.
                //      필터가 토큰을 확인한 뒤, 거기에 메모를 한다. 그러면 Spring Security 로직이 그걸 읽을 수 있다.
                //      요청이 끝나면 메모는 지워진다.
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        filterChain.doFilter(req, res);
    }

    private String resolveToken(HttpServletRequest req) {
        String header = req.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }

        return null;
    }
}
