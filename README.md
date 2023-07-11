# Getting Started

## create rsa key pair
openssl genrsa -out keypair.pem 2048

## extract public key
openssl rsa -in keypair.pem -pubout -out public.pem

## create private key in PKCS#8 format
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out private.pem

# JWKS:

    1. Jwks keys are generated on every startup and printed on the console
    2. Copy both private and public key pair json and just the public key json into jwk.json and jwk-set.json
    3. To generate xml version of the jwk-set.json 
        1. Convert jwk to pem format using https://8gwifi.org/jwkconvertfunctions.jsp
        2. Convert the pem to xml using https://raskeyconverter.azurewebsites.net/PemToXml?handler=ConvertXML
        3. Encode the xml using - https://www.base64encode.org/
        4. Copy the content to jwt:roles section in the application.yaml file 

# Postman Request

1. Get header JWT token
    > curl --location 'http://localhost:8080/jwt/token' \
   --header 'Content-Type: application/json' \
   --header 'Cookie: JSESSIONID=14260BCF46299203F39986BA21F66F6B' \
   --data '{
   "name":"seenimurugan",
   "scope": ["read", "write"]
   }'
2. Get Body JWT token
    > curl --location 'http://localhost:8080/jwt/bodytoken' \
   --header 'Content-Type: application/json' \
   --header 'Cookie: JSESSIONID=14260BCF46299203F39986BA21F66F6B' \
   --data '{
   "eblDocumentId": "123",
   "rid": "seenimurugan",
   "language": "EN",
   "code": "S15",
   "companyCode": "BOLERO",
   "timeZone": "UK",
   "signature": "seeni",
   "action": "test"
   }'
3. Access jwt secured endpoint

    > curl --location 'http://localhost:8080/jwt/secureendpoint' \
   --header 'Content-Type: text/plain' \
   --header 'Authorization: Bearer replace_me_with_above_header_jwt ' \
   --header 'Cookie: JSESSIONID=ED68AFEBC21FF3BE5BB35FB6629AECD5' \
   --data 'replace_me_with_above_body_jwt_token'


# Version:
## To use with Spring boot 2.5.14
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-jose</artifactId>
    <version>5.7.9</version>
</dependency>

