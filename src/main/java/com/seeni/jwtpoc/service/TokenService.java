package com.seeni.jwtpoc.service;

import com.seeni.jwtpoc.config.CustomTokenValidationProperties;
import com.seeni.jwtpoc.model.request.TokenInfo;
import com.seeni.jwtpoc.model.request.Wc1UserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static com.seeni.jwtpoc.config.CustomJwtAuthenticationConverter.*;

@Service
@RequiredArgsConstructor
public class TokenService {
    private final JwtEncoder encoder;
    private final CustomTokenValidationProperties customTokenValidationProperties;

    public String generateToken(TokenInfo tokenInfo) {
        Instant now = Instant.now();
        String scope = String.join(" ", Optional.ofNullable(tokenInfo.scope())
                .orElse(Set.of()));
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .audience(List.of("5436e3e3-0866-4ac1-b0c0-85c6ec8b863f"))
                .issuedAt(now)
                .notBefore(now)
                .expiresAt(now.plus(15, ChronoUnit.HOURS))
                .subject(tokenInfo.name())
                .claims(stringObjectMap -> {
                    var customClaims = Map.of(
                            "azp", customTokenValidationProperties.allowedCw1Instances(),
                            "roles", customTokenValidationProperties.roles());
                    stringObjectMap.putAll(customClaims);
                })
                .build();
        return this.encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    public String generateWc1UserDetailsToken(Wc1UserDetails wc1UserDetails) {
        Instant now = Instant.now();
//        String scope = String.join(" ", Optional.ofNullable(tokenInfo.scope())
//                .orElse(Set.of()));
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .notBefore(now)
                .expiresAt(now.plus(15, ChronoUnit.HOURS))
                .subject(wc1UserDetails.code())
                .claims(stringObjectMap -> {
                    var customClaims = Map.of(
                            EBL_DOCUMENT_ID, wc1UserDetails.eblDocumentId(),
                            RID, wc1UserDetails.rid(),
                            LANGUAGE, wc1UserDetails.language(),
                            CODE, wc1UserDetails.code(),
                            COMPANY_CODE, wc1UserDetails.companyCode(),
                            TIME_ZONE, wc1UserDetails.timeZone(),
                            SIGNATURE, wc1UserDetails.signature(),
                            ACTION, wc1UserDetails.action());
                    stringObjectMap.putAll(customClaims);
                })
                .build();
        return this.encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }
}
