package org.example.jwtpractice.config;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @GetMapping("/hello")
    public String adminHello(Authentication authentication) {
        return "관리자 " + authentication.getName() + "님, 환영합니다";
    }
}
