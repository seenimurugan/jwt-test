package com.seeni.jwtpoc.controller;

import com.seeni.jwtpoc.model.request.TokenInfo;
import com.seeni.jwtpoc.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
@RequiredArgsConstructor
public class EblController {

    private final TokenService tokenService;

    @GetMapping("/")
    public String home(Model model) {
        TokenInfo tokenInfo = tokenService.getDefaultTokenDetails();
        model.addAttribute("tokenInfo", tokenInfo);
        return "userDetailsForm";
    }

    @RequestMapping(value = "/generateToken", method = RequestMethod.POST)
    public String generateToken(Model model, @ModelAttribute TokenInfo tokenInfo) {
        TokenInfo tokenDetails = tokenService.createTokenInfoWithJwt(tokenInfo);
        model.addAttribute("tokenInfo", tokenDetails);
        return "tokenDetailsFrom";
    }

    @RequestMapping(value = "/invokewebservice", method = RequestMethod.POST)
    public String invokeWebservice(Model model, @ModelAttribute TokenInfo tokenInfo) {
        tokenService.redirectToWebService(tokenInfo);
        return "redirectForm";
    }

}
