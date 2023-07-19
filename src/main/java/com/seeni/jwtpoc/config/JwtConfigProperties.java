package com.seeni.jwtpoc.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(prefix = "jwt")
public record JwtConfigProperties(List<String> allowedCw1Instances,
                                  List<String> roles,
                                  List<String> postRequestPath,
                                  List<String> corsAllowedOrigins,
                                  String eblUrl,
                                  String audience) {
}
