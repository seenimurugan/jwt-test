package com.seeni.jwtpoc.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.seeni.jwtpoc.config.JwtConfigProperties;
import com.seeni.jwtpoc.model.request.TokenInfo;
import com.seeni.jwtpoc.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.util.List;
import java.util.Map;

@Controller
@RequiredArgsConstructor
public class EblController {

	public static final String KEYS = "keys";

	private final TokenService tokenService;
	private final JwtConfigProperties jwtConfigProperties;
	private final ObjectMapper objectMapper;

	@GetMapping("/")
	public String home(Model model) throws JsonProcessingException {
		var headerRsaKey = tokenService.generateKey();
		var bodyRsaKey = tokenService.generateKey();
		var headerJwk = Map.of(KEYS, List.of(headerRsaKey.toJSONObject()));
		var bodyJwk = Map.of(KEYS, List.of(bodyRsaKey.toJSONObject()));
		var tokenInfo = TokenInfo.builder()
				.eblUrl(jwtConfigProperties.eblUrl())
				.headerRsaKeyPair(objectMapper.writeValueAsString(headerJwk))
				.bodyRsaKeyPair(objectMapper.writeValueAsString(bodyJwk))
				.audience(jwtConfigProperties.audience())
				.cw1Instance(jwtConfigProperties.allowedCw1Instance())
				.issuerUri(jwtConfigProperties.getIssuerUri())
				.build();
		model.addAttribute("tokenInfo", tokenInfo);
		return "tokenInfoForm";
	}

	@RequestMapping(value = "/generateToken", method = RequestMethod.POST)
	public String redirectToExternalUrl(Model model, @ModelAttribute TokenInfo tokenInfo) {
		var tokenDetails = tokenService.createTokenInfoWithJwt(tokenInfo);
		model.addAttribute("tokenInfo", tokenDetails);
		return "eblForm";
	}

}
