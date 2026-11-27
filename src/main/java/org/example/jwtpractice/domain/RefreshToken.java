package org.example.jwtpractice.domain;

import jakarta.persistence.*;

@Entity
@Table(name = "refresh_tokens")
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false, length = 500)
    private String token;

    protected RefreshToken() {}

    public RefreshToken(String username, String token) {
        this.username = username;
        this.token = token;
    }

    public String getToken() { return token; }
    public void update(String token) { this.token = token; }
}
