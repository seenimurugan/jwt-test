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
		var tokenInfo = tokenService.getDefaultTokenDetails();
		model.addAttribute("tokenInfo", tokenInfo);
		return "tokenInfoForm";
	}

	@RequestMapping(value = "/generateToken", method = RequestMethod.POST)
	public String redirectToExternalUrl(Model model, @ModelAttribute TokenInfo tokenInfo) {
		var tokenDetails = tokenService.createTokenInfoWithJwt(tokenInfo);
		if (tokenInfo.useWebService()) {
			tokenService.redirectToWebService(tokenDetails);
		} else {
			model.addAttribute("tokenInfo", tokenDetails);
		}
		return "eblForm";
	}

}
