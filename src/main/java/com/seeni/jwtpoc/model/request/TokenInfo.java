package com.seeni.jwtpoc.model.request;

import lombok.Builder;

public record TokenInfo(String eblDocumentId, String rid, String language, String userCode,
                        String companyCode, String timeZone, String cw1Instance, String action,
                        String issuerUri, String bodyToken, String headerToken, String eblUrl,
                        String headerRsaKeyPair, String bodyRsaKeyPair, String audience,
                        String decodedBodyToken, String decodedHeaderToken) {
    @Builder
    public TokenInfo {}
}
