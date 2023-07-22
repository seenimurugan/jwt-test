package com.seeni.jwtpoc.config;

import lombok.SneakyThrows;
import org.springframework.boot.configurationprocessor.json.JSONObject;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(prefix = "jwt")
public record JwtConfigProperties(String allowedCw1Instance,
                                  List<String> roles,
                                  List<String> postRequestPath,
                                  List<String> corsAllowedOrigins,
                                  String eblUrl,
                                  String audience, JSONObject openidConfiguration) {
    public static final String ISSUER = "issuer";
    @SneakyThrows
    public String getIssuerUri() {
        return (String) openidConfiguration.get(ISSUER);
    }
}
