package com.security.securityProject.controller;



import com.security.securityProject.dto.AuthRequest;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api")
public class ResourceController {

    @GetMapping("/public")
    public Mono<String> publicEndpoint() {
        return Mono.just("Bu herkese açık bir endpoint.");
    }

    @PostMapping("/user")
    public Mono<String> userEndpoint(@RequestBody AuthRequest authentication) {
        return Mono.just( "Merhaba " + authentication.getEmail() + "! Bu sadece kullanıcılara özel bir endpoint.");
    }

    @PostMapping("/admin")
    public Mono<String> adminEndpoint(@RequestBody AuthRequest authentication) {
        return Mono.just( "Merhaba Admin " + authentication.getEmail() + "! Bu sadece yöneticilere özel bir endpoint.");
    }
}