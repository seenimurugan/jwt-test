package com.seeni.jwtpoc.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.View;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;

@RestController
@RequestMapping(value = "/form")
@Slf4j
public class FormController {
    @GetMapping
    public String greeting(Principal principal) {
        return "Hello ".concat(principal.getName()).concat(" from Form Controller");
    }

    @PostMapping("/ebl")
    public ModelAndView eblPost(Principal principal, HttpServletRequest request) {
        log.info("principle[{}]", principal);
        request.setAttribute(
                View.RESPONSE_STATUS_ATTRIBUTE, HttpStatus.FOUND);
        return new ModelAndView("redirect:/form/ebl");
    }

    @GetMapping("/ebl")
    public String eblGet(Principal principal) {
        log.info("principle[{}]", principal);
        return "Hello ".concat(principal.getName()).concat(" from JWT Controller");
    }
}
