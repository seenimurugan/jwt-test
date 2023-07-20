package com.seeni.jwtpoc.service;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.security.oauth2.jwt.*;
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
    public static final String ISSUER = "issuer";
    private final JwtConfigProperties jwtConfigProperties;
    private final ObjectMapper objectMapper;

    private final Map<String, RSAKey> keysMap = createFIFOMap(100);

    @SneakyThrows
    public Jwt generateHeaderToken(TokenInfo tokenInfo) {

        var headerRsaKeyPair = tokenInfo.headerRsaKeyPair();
        var headerJwkSet = getJwkSet(headerRsaKeyPair);
        var headerEncoder = getJwtEncoder(headerJwkSet);
        addToCache(headerJwkSet);

        var bodyRsaKeyPair = tokenInfo.bodyRsaKeyPair();
        List<String> roles = getPublicKeyAsRoles(bodyRsaKeyPair);

        var config = jwtConfigProperties.openidConfiguration();
        var issuer = (String) config.get(ISSUER);

        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .audience(List.of(tokenInfo.audience()))
                .issuedAt(now)
                .notBefore(now)
                .expiresAt(now.plus(15, ChronoUnit.HOURS))
                .subject(tokenInfo.userCode())
                .claims(stringObjectMap -> {
                    var customClaims = Map.of(
                            "azp", jwtConfigProperties.allowedCw1Instances(),
                            "roles", roles);
                    stringObjectMap.putAll(customClaims);
                })
                .build();
        return headerEncoder.encode(JwtEncoderParameters.from(claims));
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

    @SneakyThrows
    public TokenInfo createTokenInfoWithJwt(TokenInfo tokenInfo) {
        var bodyTokenJwt = generateBodyToken(tokenInfo);
        var headerTokenJwt = generateHeaderToken(tokenInfo);
        var encodedBodyToken = bodyTokenJwt.getTokenValue();
        var encodedHeaderToken = headerTokenJwt.getTokenValue();

        var bodyTokenJwtClaims = bodyTokenJwt.getClaims();
        var headerTokenJwtClaims = headerTokenJwt.getClaims();
        var bodyTokenJwtClaimsAsString = objectMapper.writeValueAsString(bodyTokenJwtClaims);
        var headerTokenJwtClaimsAsString = objectMapper.writeValueAsString(headerTokenJwtClaims);

        String eblUrl = tokenInfo.eblUrl() != null ? tokenInfo.eblUrl() : jwtConfigProperties.eblUrl();

        return TokenInfo.builder()
                .headerToken(encodedHeaderToken)
                .bodyToken(encodedBodyToken)
                .decodedHeaderToken(headerTokenJwtClaimsAsString)
                .decodedBodyToken(bodyTokenJwtClaimsAsString)
                .eblUrl(eblUrl)
                .build();
    }

    public Jwt generateBodyToken(TokenInfo tokenInfo) {

        var bodyRsaKeyPair = tokenInfo.bodyRsaKeyPair();
        var bodyJwkSet = getJwkSet(bodyRsaKeyPair);
        var bodyEncoder = getJwtEncoder(bodyJwkSet);

        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .notBefore(now)
                .expiresAt(now.plus(15, ChronoUnit.HOURS))
                .subject(tokenInfo.userCode())
                .claims(stringObjectMap -> {
                    var customClaims = Map.of(
                            EBL_DOCUMENT_ID, tokenInfo.eblDocumentId(),
                            RID, tokenInfo.rid(),
                            LANGUAGE, tokenInfo.language(),
                            CODE, tokenInfo.userCode(),
                            COMPANY_CODE, tokenInfo.companyCode(),
                            TIME_ZONE, tokenInfo.timeZone(),
                            SIGNATURE, tokenInfo.signature(),
                            ACTION, tokenInfo.action());
                    stringObjectMap.putAll(customClaims);
                })
                .build();
        return bodyEncoder.encode(JwtEncoderParameters.from(claims));
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
