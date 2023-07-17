package com.seeni.jwtpoc.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;


@Service
@RequiredArgsConstructor
@Slf4j
public class XmlRSAKeyParser {

    public static final String MODULES_NAME = "Modulus";
    public static final String EXPONENT_NAME = "Exponent";
    private static final String[] PUBLIC_KEY_XML_NODES = {MODULES_NAME, EXPONENT_NAME};
    public static final String KID_NAME = "kid";
    public static final String KID_VALUE = "1";
    public static final String MODULUS = "n";
    public static final String EXPONENT = "e";
    public static final String ALG_FAMILY = "kty";
    private final ObjectMapper objectMapper;

    public RSAKey convertXmlRsaToRSAKey(String xmlContentString) {
        byte[] decodedXmlContentString = b64decode(xmlContentString);
        Optional<Document> XMLSecKeyDoc = parseXMLFile(decodedXmlContentString);

        return XMLSecKeyDoc
                .filter(this::checkXMLRSAKey)
                .map(this::getRSAKeyObject)
                .orElse(null);
    }

    private boolean checkXMLRSAKey(Document xmlDoc) {
        Node root = xmlDoc.getFirstChild();
        NodeList children = root.getChildNodes();

        return Stream.of(PUBLIC_KEY_XML_NODES)
                .anyMatch(wantedNode -> IntStream.range(0, children.getLength()).boxed()
                        .anyMatch(index -> wantedNode.equals(children.item(index).getNodeName())));
    }

    @SneakyThrows
    private RSAKey getRSAKeyObject(Document xmlDoc) {
        log.info("xml rsa key validation passed!!!");
        Node root = xmlDoc.getFirstChild();
        NodeList children = root.getChildNodes();

        Map<String, Object> modulusAndExponentMap = getModulusAndExponentAsMap(children);
        modulusAndExponentMap.put(KID_NAME, KID_VALUE);

        var jwkMap = Map.of(
                ALG_FAMILY, "RSA",
                EXPONENT, modulusAndExponentMap.get(EXPONENT_NAME),
                KID_NAME, KID_VALUE,
                MODULUS, modulusAndExponentMap.get(MODULES_NAME));

        var jwksMap = Map.<String, Object>of("keys", List.of(jwkMap));
        log.info("converted jwks key {}", objectMapper.writeValueAsString(jwksMap));
        try {
           JWKSet jwkSet = JWKSet.parse(jwksMap);
           return jwkSet.getKeyByKeyId(KID_VALUE).toRSAKey();
        } catch (Exception e) {
            log.error("Exception in creating RSA public key", e);
        }
        return null;
    }

    private Map<String, Object> getModulusAndExponentAsMap(NodeList children) {
        return IntStream.range(0, children.getLength())
                .boxed()
                .map(children::item)
                .map(node -> {
                    String textValue = node.getTextContent();
                    if (node.getNodeName().equals(MODULES_NAME)) {
                        return Map.of(MODULES_NAME, textValue);
                    } else if (node.getNodeName().equals(EXPONENT_NAME)) {
                        return Map.of(EXPONENT_NAME, textValue);
                    } else {
                        return Map.<String, String>of();
                    }
                })
                .flatMap(map -> map.entrySet().stream())
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    private Optional<Document> parseXMLFile(byte[] xmlFileContent) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new ByteArrayInputStream(xmlFileContent));
            return Optional.of(doc);
        } catch (Exception e) {
            log.error("Exception in parsing xml", e);
            return Optional.empty();
        }
    }

    public static String b64encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data).trim();
    }

    public static byte[] b64decode(String data) {
        return Base64.getDecoder().decode(data.trim());
    }
}
