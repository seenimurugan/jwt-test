package com.seeni.jwtpoc.model.request;

import lombok.Builder;

public record TokenInfo(String eblDocumentId, String rid, String language, String userCode,
                        String companyCode, String timeZone, String signature, String action,
                        String bodyToken, String headerToken, String eblUrl, String headerRsaKeyPair,
                        String bodyRsaKeyPair, String audience, String decodedBodyToken, String decodedHeaderToken) {
    @Builder
    public TokenInfo {}
}
