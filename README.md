# Getting Started

# JWKS:

    1. Jwks keys can be generated from /keys endpoint and also every startup it gets printed on the console
    2. Copy both private key and public key json into jwk.json and jwk-set.json
    3. To populate the roles claim in the header JWT follow the below steps
        1. Copy everything from jwk-set.json
        2. Convert jwk to pem format using https://8gwifi.org/jwkconvertfunctions.jsp
        3. Convert the pem to xml using https://raskeyconverter.azurewebsites.net/PemToXml?handler=ConvertXML
        4. Encode the xml using - https://www.base64encode.org/
        5. Copy the content to jwt:roles section in the application.yaml file 

# Postman Request

1. Get access token
    > curl --location 'http://localhost:8080/jwt/token' \
   --header 'Content-Type: application/json' \
   --data '{
   "name":"seenimurugan",
   "scope": ["read", "write"]
   }'
2. Get Data token(JWT token contains user information)
    > curl --location 'http://localhost:8080/jwt/bodytoken' \
   --header 'Content-Type: application/json' \
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
   --header 'Content-Type: application/json' \
   --data 'access_token=<Replace_generated_access_token>&data=<Replace_generated_data_token>'

4. Generate Private and Public keys
   
   > curl --location --request GET 'http://localhost:8080/jwt/keys' \
   --header 'Content-Type: application/json' \
   --data '{
   "name":"seenimurugan",
   "scope": ["read", "write"]
   }'

# Pem format

## create rsa key pair
openssl genrsa -out keypair.pem 2048

## extract public key
openssl rsa -in keypair.pem -pubout -out public.pem

## create private key in PKCS#8 format
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out private.pem

# Version:
## To use with Spring boot 2.5.14
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-jose</artifactId>
    <version>5.7.9</version>
</dependency>

