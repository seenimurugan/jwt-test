package com.seeni.jwtpoc.controller;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.seeni.jwtpoc.config.JwtConfigProperties;
import com.seeni.jwtpoc.service.TokenService;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping(value = "/jwks/v1.0")
@Slf4j
@RequiredArgsConstructor
public class JwksController {

    private final TokenService tokenService;
    private final JwtConfigProperties jwtConfigProperties;
    private final ObjectMapper objectMapper;

    @GetMapping(path = "/.well-known/jwks.json", produces = APPLICATION_JSON_VALUE)
    public Map<String, Object> keySets() {
        return tokenService.getPublicKeys();
    }

    @SneakyThrows
    @GetMapping(path = "/.well-known/openid-configuration", produces = APPLICATION_JSON_VALUE)
    public String openIdConfiguration() {
        return objectMapper.readTree(jwtConfigProperties.openidConfiguration().toString()).toPrettyString();
    }

}
