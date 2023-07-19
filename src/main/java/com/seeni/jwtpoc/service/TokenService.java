package com.seeni.jwtpoc.service;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.seeni.jwtpoc.config.JwtConfigProperties;
import com.seeni.jwtpoc.model.request.TokenInfo;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class TokenService {

    public static final String EBL_DOCUMENT_ID = "eblDocumentId";
    public static final String RID = "rid";
    public static final String LANGUAGE = "language";
    public static final String CODE = "code";
    public static final String COMPANY_CODE = "companyCode";
    public static final String TIME_ZONE = "timeZone";
    public static final String SIGNATURE = "signature";
    public static final String ACTION = "action";
    private final JwtConfigProperties jwtConfigProperties;

    private final Map<String, RSAKey> keysMap = createFIFOMap(5);

    public String generateHeaderToken(TokenInfo tokenInfo) {

        var headerRsaKeyPair = tokenInfo.headerRsaKeyPair();
        var headerJwkSet = getJwkSet(headerRsaKeyPair);
        var headerEncoder = getJwtEncoder(headerJwkSet);
        addToCache(headerJwkSet);

        var bodyRsaKeyPair = tokenInfo.bodyRsaKeyPair();
        List<String> roles = getPublicKeyAsRoles(bodyRsaKeyPair);

        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .audience(List.of("5436e3e3-0866-4ac1-b0c0-85c6ec8b863f"))
                .issuedAt(now)
                .notBefore(now)
                .expiresAt(now.plus(15, ChronoUnit.HOURS))
                .subject(tokenInfo.code())
                .claims(stringObjectMap -> {
                    var customClaims = Map.of(
                            "azp", jwtConfigProperties.allowedCw1Instances(),
                            "roles", roles);
                    stringObjectMap.putAll(customClaims);
                })
                .build();
        return headerEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    private List<String> getPublicKeyAsRoles(String bodyRsaKeyPair) {
        var bodyJwkSet = getJwkSet(bodyRsaKeyPair);
        var xmlRsaPublicKey = toXmlRsaPublicKey(bodyJwkSet);

        var encodedXmlRsaPublicKey = b64encode(xmlRsaPublicKey.getBytes());
        var part0 = encodedXmlRsaPublicKey.substring(0, 100);
        var part1 = encodedXmlRsaPublicKey.substring(100, 200);
        var part2 = encodedXmlRsaPublicKey.substring(200);
        return List.of("0:" + part0, "1:" + part1, "2:" + part2);
    }

    public String generateBodyToken(TokenInfo tokenInfo) {

        var bodyRsaKeyPair = tokenInfo.bodyRsaKeyPair();
        var bodyJwkSet = getJwkSet(bodyRsaKeyPair);
        var bodyEncoder = getJwtEncoder(bodyJwkSet);

        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .notBefore(now)
                .expiresAt(now.plus(15, ChronoUnit.HOURS))
                .subject(tokenInfo.code())
                .claims(stringObjectMap -> {
                    var customClaims = Map.of(
                            EBL_DOCUMENT_ID, tokenInfo.eblDocumentId(),
                            RID, tokenInfo.rid(),
                            LANGUAGE, tokenInfo.language(),
                            CODE, tokenInfo.code(),
                            COMPANY_CODE, tokenInfo.companyCode(),
                            TIME_ZONE, tokenInfo.timeZone(),
                            SIGNATURE, tokenInfo.signature(),
                            ACTION, tokenInfo.action());
                    stringObjectMap.putAll(customClaims);
                })
                .build();
        return bodyEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    @SneakyThrows
    JwtEncoder getJwtEncoder(JWKSet jwkSet) {
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwkSet.getKeys()));
        return new NimbusJwtEncoder(jwks);
    }

    @SneakyThrows
    JWKSet getJwkSet(String rsaKeyPair) {
        return JWKSet.parse(rsaKeyPair);
    }

    @SneakyThrows
    public String toXmlRsaPublicKey(JWKSet jwkSet) {
        return jwkSet.getKeys().stream()
                .map(JWK::toPublicJWK)
                .map(JWK::toRSAKey)
                .map(rsaKey -> {
                    var modulus = rsaKey.getModulus();
                    var exponent = rsaKey.getPublicExponent();
                    return "<RSAKeyValue> <Modulus>" + modulus + "</Modulus><Exponent>" + exponent + "</Exponent></RSAKeyValue>";
                })
                .findFirst()
                .orElse("");
    }

    @SneakyThrows
    public RSAKey generateKey() {
        var rsaKey = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
                .keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
                .generate();
        log.info("private and public key [{}]", rsaKey);
        log.info("public key [{}]", rsaKey.toPublicJWK());
        return rsaKey;
    }

    public static <K, V> Map<K, V> createFIFOMap(final int maxEntries) {
        return new LinkedHashMap<K, V>(maxEntries * 10 / 7, 0.7f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
                return size() > maxEntries;
            }
        };
    }

    public void addToCache(JWKSet jwkSet) {
        var publicKey = jwkSet.getKeys().stream()
                .map(JWK::toPublicJWK)
                .collect(Collectors.toMap(JWK::toJSONString, JWK::toRSAKey));
        this.keysMap.putAll(publicKey);
    }

    public Map<String, Object> getPublicKeys() {
        var keys = keysMap.values().stream()
                .map(RSAKey::toJSONObject)
                .collect(Collectors.toSet());
        return Map.of("keys", keys);
    }

    public static String b64encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data).trim();
    }

}
