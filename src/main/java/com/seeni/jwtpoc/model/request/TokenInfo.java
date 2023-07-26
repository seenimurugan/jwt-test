package com.seeni.jwtpoc.model.request;

import lombok.Builder;

import java.util.Map;

public record TokenInfo(String eblDocumentId, String rid, String language, String userCode,
                        String companyCode, String timeZone, Map<String, String> cw1Instances, String action,
                        String issuerUri, String bodyToken, String headerToken, Map<String, String> galileoEndpoints,
                        String headerRsaKeyPair, String bodyRsaKeyPair, String audience,
                        String decodedBodyToken, String decodedHeaderToken,
                        String cw1Instance, String galileoEndpoint, String publicKeyUri) {
    @Builder
    public TokenInfo {}
}
