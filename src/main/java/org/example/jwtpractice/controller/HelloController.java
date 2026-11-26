package org.example.jwtpractice.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/api/hello")
    public String hello(Authentication authentication) {
        return "안녕하세요, " + authentication.getName() + "님";
    }
}
