package com.seeni.jwtpoc.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

@ConfigurationProperties(prefix = "rsa")
public record JwtSigningKey(Resource headerRsaKeyPair, Resource bodyRsaKeyPair) {
}
