package com.seeni.jwtpoc;

import com.seeni.jwtpoc.config.CustomTokenValidationProperties;
import com.seeni.jwtpoc.config.JwtSigningKey;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({JwtSigningKey.class, CustomTokenValidationProperties.class})
public class JwtPocApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtPocApplication.class, args);
	}

}
