package com.seeni.jwtpoc.controller;


import com.nimbusds.jose.jwk.JWKSet;
import com.seeni.jwtpoc.model.request.TokenInfo;
import com.seeni.jwtpoc.model.request.Wc1UserDetails;
import com.seeni.jwtpoc.service.TokenService;
import com.seeni.jwtpoc.service.XmlToPemConverter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.Map;

@RestController
@RequestMapping(value = "/jwt")
@Slf4j
@RequiredArgsConstructor
public class JwtController {

    private final TokenService tokenService;
    private final XmlToPemConverter xmlToPemConverter;
    private final JWKSet jwkSet;

    @GetMapping("/ebl")
    public String greeting(Principal principal) {
        return "Hello ".concat(principal.getName()).concat(" from JWT Controller");
    }

    @PostMapping("/secureendpoint")
    public String secureEndpoint(Authentication authentication) {
        var wc1UserDetails = (Wc1UserDetails) authentication.getPrincipal();
        log.info("Wc1 User Details[{}]", wc1UserDetails);
        return "Hello ".concat(wc1UserDetails.code()).concat(" ").concat(wc1UserDetails.companyCode()).concat(" from JWT Controller");
    }

    @PostMapping(path = "/token")
    public String token(@RequestBody TokenInfo tokenInfo) {
        log.info("Token requested for user: [{}]", tokenInfo);
        String token = tokenService.generateToken(tokenInfo);
        log.info("Token granted: {}", token);
        return token;
    }

    @PostMapping(path = "/bodytoken")
    public String bodyToken(@RequestBody Wc1UserDetails wc1UserDetails) {
        log.info("Token requested for user: [{}]", wc1UserDetails.code());
        String token = tokenService.generateWc1UserDetailsToken(wc1UserDetails);
        log.info("Token granted: {}", token);
        return token;
    }

    @PostMapping(path = "/convert")
    public String getPemFormat(@RequestBody Map<Integer, String> xmlKey) {
        String xmlRsaKey = String.join("", xmlKey.get(0), xmlKey.get(1), xmlKey.get(2));
        return xmlToPemConverter.convertXmlRsaToPem(xmlRsaKey);
    }

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> keys() {
        return this.jwkSet.toJSONObject();
    }
}
