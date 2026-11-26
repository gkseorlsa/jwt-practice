package org.example.jwtpractice.config;

import org.example.jwtpractice.jwt.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // csrf disable: 세션이나 쿠키 대신 Authorization 헤더로 토큰을 보내는 구조라 CSRF 필요 없어서 꺼둔다.
    // STATELESS: 서버가 세션을 만들지 않는다. 인증 정보는 매 요청의 토큰이 전부이다.
    //      JWT 구조는 세션에 로그인 상태를 저장하지 않는 방식을 사용하므로 매 요청마다 토큰으로 누구인지 다시 알려줘야 한다.
    // formLogin, httpBasic: Spring Security 기본 로그인 방식
    // authorizeHttpRequests: URL 별로 누구에게 허용할지 규칙을 정할 수 있다.
    // addFilterBefore: Spring Security의 기본 로그인 필터보다 앞에 내가 직접 만든 필터를 끼워 넣는다는 의미이다.
    //      인증 판단이 일어나기 전에 우리가 먼저 SecurityContext를 채워놔야 한다.

    // 비밀번호는 평문이 아니라 BCrypt 해시로 저장된다.

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())
                .sessionManagement(s -> s
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**", "/error").permitAll()
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .anyRequest()
                        .authenticated()
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
        ;

        return http.build();
    }
}
