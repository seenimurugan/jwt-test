package com.seeni.jwtpoc.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping(value = "/basic/auth")
public class BasicAuthController {
    @GetMapping
    public String greeting(Principal principal) {
        return "Hello ".concat(principal.getName()).concat(" from BasicAuth Controller");
    }


}
