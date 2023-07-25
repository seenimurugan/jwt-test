package com.seeni.jwtpoc.config;

import lombok.SneakyThrows;
import org.springframework.boot.configurationprocessor.json.JSONObject;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;
import java.util.Map;

@ConfigurationProperties(prefix = "jwt")
public record JwtConfigProperties(Map<String, String> allowedCw1Instances,
                                  Map<String, String> galileoEndpoints,
                                  List<String> roles,
                                  List<String> postRequestPath,
                                  List<String> corsAllowedOrigins,
                                  String audience,
                                  JSONObject openidConfiguration,
                                  String azrPublicKeyUrl,
                                  String rdpWebService) {
    public static final String ISSUER = "issuer";
    @SneakyThrows
    public String getIssuerUri() {
        return (String) openidConfiguration.get(ISSUER);
    }
}
