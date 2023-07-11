package com.seeni.jwtpoc.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@ConfigurationProperties(prefix = "rsa")
public record JwtSigningKey(RSAPublicKey publicKey, RSAPrivateKey privateKey, Resource jwkSet, Resource jwk) {
}
