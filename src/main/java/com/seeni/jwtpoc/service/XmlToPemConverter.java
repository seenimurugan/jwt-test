package com.seeni.jwtpoc.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;


@Service
@Slf4j
public class XmlToPemConverter {

    public static final String MODULES_NAME = "Modulus";
    public static final String EXPONENT_NAME = "Exponent";
    private static final String[] PUBLIC_KEY_XML_NODES = {MODULES_NAME, EXPONENT_NAME};
    public static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
    public static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";
    public static final String PUBLIC_KEY_ALGORITHM = "RSA";


    public String convertXmlRsaToPem(String xmlContentString) {

        byte[] decodedXmlContentString = b64decode(xmlContentString);
        Optional<Document> XMLSecKeyDoc = parseXMLFile(decodedXmlContentString);

        return XMLSecKeyDoc
                .filter(this::checkXMLRSAKey)
                .map(this::convertXMLRSAPublicKeyToPEM)
                .orElse("");

    }

    private boolean checkXMLRSAKey(Document xmlDoc) {

        Node root = xmlDoc.getFirstChild();
        NodeList children = root.getChildNodes();

        return Stream.of(PUBLIC_KEY_XML_NODES)
                .anyMatch(wantedNode -> IntStream.range(0, children.getLength()).boxed()
                        .anyMatch(index -> wantedNode.equals(children.item(index).getNodeName())));

    }

    private String convertXMLRSAPublicKeyToPEM(Document xmlDoc) {

        Node root = xmlDoc.getFirstChild();
        NodeList children = root.getChildNodes();

        Map<String, BigInteger> modulusAndExponentMap = getModulusAndExponentAsMap(children);

        try {
            BigInteger modulus = modulusAndExponentMap.get(MODULES_NAME);
            BigInteger exponent = modulusAndExponentMap.get(EXPONENT_NAME);

            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);

            KeyFactory keyFactory = KeyFactory.getInstance(PUBLIC_KEY_ALGORITHM);
            PublicKey key = keyFactory.generatePublic(keySpec);
            return b64encode(key.getEncoded());

        } catch (Exception e) {
            log.error("Exception in creating RSA public key", e);
        }
        return null;
    }

    private Map<String, BigInteger> getModulusAndExponentAsMap(NodeList children) {
        return IntStream.range(0, children.getLength())
                .boxed()
                .map(children::item)
                .map(node -> {
                    String textValue = node.getTextContent();
                    if (node.getNodeName().equals(MODULES_NAME)) {
                        return Map.of(MODULES_NAME, new BigInteger(1, b64decode(textValue)));
                    } else if (node.getNodeName().equals(EXPONENT_NAME)) {
                        return Map.of(EXPONENT_NAME, new BigInteger(1, b64decode(textValue)));
                    } else {
                        return Map.<String, BigInteger>of();
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
