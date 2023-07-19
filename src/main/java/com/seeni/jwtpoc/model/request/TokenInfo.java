package com.seeni.jwtpoc.model.request;

import lombok.Builder;

public record TokenInfo(String eblDocumentId, String rid, String language, String code,
                        String companyCode, String timeZone, String signature, String action,
                        String bodyToken, String headerToken, String eblUrl, String headerRsaKeyPair,
                        String bodyRsaKeyPair, String audience) {
    @Builder
    public TokenInfo {}
}
