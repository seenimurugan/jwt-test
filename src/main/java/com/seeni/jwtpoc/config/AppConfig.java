package com.seeni.jwtpoc.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.AntPathMatcher;

@Configuration
public class AppConfig {

    @Bean
    public AntPathMatcher antPathMatcher() {
        final var antPathMatcher = new AntPathMatcher();
        antPathMatcher.setCaseSensitive(false);
        return antPathMatcher;
    }

}
