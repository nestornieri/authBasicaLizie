package com.example.oauth2Ser;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication
public class Oauth2SerApplication {

	public static void main(String[] args) {
		SpringApplication.run(Oauth2SerApplication.class, args);
	}

}
