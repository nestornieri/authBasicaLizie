package com.example.oauth2Ser;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class SecureController {

    @GetMapping("/secure-data")
    public ResponseEntity<String> getSecureData() {
        return ResponseEntity.ok("¡Este es un recurso protegido con OAuth2!");
    }
}