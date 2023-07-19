package com.seeni.jwtpoc.controller;


import com.seeni.jwtpoc.service.TokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping(value = "/jwt")
@Slf4j
@RequiredArgsConstructor
public class JwtController {

    private final TokenService tokenService;

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> keys() {
        return tokenService.getPublicKeys();
    }

}
