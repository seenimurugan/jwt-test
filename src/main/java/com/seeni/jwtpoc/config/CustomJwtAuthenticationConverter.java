package com.seeni.jwtpoc.config;

import com.nimbusds.jose.JOSEException;
import com.seeni.jwtpoc.model.request.Wc1UserDetails;
import com.seeni.jwtpoc.service.XmlRSAPublicKeyToRSAKeyObjectConverter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;

import java.util.*;
import java.util.stream.Collectors;

import static com.seeni.jwtpoc.config.RequestBodyReadFilter.REQUEST_BODY;
import static org.springframework.web.context.request.RequestAttributes.SCOPE_REQUEST;

@Component
@RequiredArgsConstructor
@Slf4j
public class CustomJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    public static final String EBL_DOCUMENT_ID = "eblDocumentId";
    public static final String RID = "rid";
    public static final String LANGUAGE = "language";
    public static final String CODE = "code";
    public static final String COMPANY_CODE = "companyCode";
    public static final String TIME_ZONE = "timeZone";
    public static final String SIGNATURE = "signature";
    public static final String ACTION = "action";
    private final Map<String, JwtDecoder> jwtDecoderStore = new HashMap<>();
    private final XmlRSAPublicKeyToRSAKeyObjectConverter xmlToJwkSetConverter;

    public AbstractAuthenticationToken convert(Jwt jwt) {
        var claims = jwt.getClaims();
        var roles = Optional.ofNullable(claims.get("roles"))
                .map(o -> (List<String>) o)
                .orElse(List.of());
        var xmlPublicKey = roles.stream()
                .map(splitJwt -> {
                    var position = (int) splitJwt.charAt(0);
                    var actualString = splitJwt.substring(2);
                    return Map.of(position, actualString);
                })
                .flatMap(map -> map.entrySet().stream())
                .sorted(Map.Entry.comparingByKey(Comparator.naturalOrder()))
                .map(Map.Entry::getValue)
                .collect(Collectors.joining());

        var jwtDecoder = getJwtDecoder(xmlPublicKey);

        var requestAttributes = RequestContextHolder.getRequestAttributes();
        var requestBody = Optional.ofNullable(requestAttributes)
                .map(attribute -> attribute.getAttribute(REQUEST_BODY, SCOPE_REQUEST))
                .map(String::valueOf);

        var decodedJwt = requestBody.map(jwtDecoder::decode);

        var wc1UserDetails = decodedJwt
                .map(jwt1 -> getUserDetailsFromClaims(jwt1.getClaims())).orElse(null);

        return new UsernamePasswordAuthenticationToken(wc1UserDetails, decodedJwt.orElse(null), null);

    }

    private JwtDecoder getJwtDecoder(String xmlPublicKey) {
        return Optional.ofNullable(jwtDecoderStore.get(xmlPublicKey))
                .orElseGet(() -> {
                    var rsaKey = xmlToJwkSetConverter.convertXmlRsaToRSAKeyObject(xmlPublicKey);
                    try {
                        var jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();
                        jwtDecoderStore.put(xmlPublicKey, jwtDecoder);
                        return jwtDecoder;
                    } catch (JOSEException e) {
                        log.error("Exception when converting RSAKey to RSAPublicKey", e);
                        throw new RuntimeException(e);
                    }
                });
    }

    private Wc1UserDetails getUserDetailsFromClaims(Map<String, Object> claims) {
        return new Wc1UserDetails(claimAsString(claims.get(EBL_DOCUMENT_ID)),
                claimAsString(claims.get(RID)),
                claimAsString(claims.get(LANGUAGE)),
                claimAsString(claims.get(CODE)),
                claimAsString(claims.get(COMPANY_CODE)),
                claimAsString(claims.get(TIME_ZONE)),
                claimAsString(claims.get(SIGNATURE)),
                claimAsString(claims.get(ACTION)));
    }

    private String claimAsString(Object claim) {
        return Optional.ofNullable(claim)
                .map(String::valueOf)
                .orElse(null);
    }
}
