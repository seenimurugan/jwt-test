package com.seeni.jwtpoc.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.ConversionService;
import org.springframework.core.convert.support.DefaultConversionService;

@Configuration
@RequiredArgsConstructor
public class AppConfig {
    private final JSONObjectConverter jsonObjectConverter;

    @Bean
    public ConversionService conversionService() {
        DefaultConversionService service = new DefaultConversionService();
        service.addConverter(jsonObjectConverter);
        return service;
    }
}
