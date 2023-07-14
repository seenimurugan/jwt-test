package com.seeni.jwtpoc.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping(value = "/form")
@Slf4j
public class FormController {
    @GetMapping
    public String greeting(Principal principal) {
        return "Hello ".concat(principal.getName()).concat(" from Form Controller");
    }

    @GetMapping("/ebl")
    public String eblGet(Principal principal) {
        log.info("principle[{}]", principal);
        return "Hello ".concat(principal.getName()).concat(" from Form Controller");
    }
}
