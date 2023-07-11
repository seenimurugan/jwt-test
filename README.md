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
   --header 'Authorization: Bearer eyJraWQiOiJ3YzEtand0LWRlbW8iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzZWVuaW11cnVnYW4iLCJhdWQiOiI1NDM2ZTNlMy0wODY2LTRhYzEtYjBjMC04NWM2ZWM4Yjg2M2YiLCJuYmYiOjE2ODkxMDE2OTcsImF6cCI6WyI1NDM2ZTNlMy0wODY2LTRhYzEtYjBjMC04NWM2ZWM4Yjg2M2IiXSwicm9sZXMiOlsiMTpWV3RuTldGeVZ6RXZhSE5xTVhCUVRtd3dZWE50ZGtWQ1VFeHNZbFZrZVU1VFdIbDBUVzFyYUVWek9UUk9UblJoZGtZekwzaDVUM05UVWpsaWRraFlhM05hUTNoMlZVUmpPVU5EVlU0elRsSjZTVWhDU0UxUlJHNW1WSHA0Ykd0NmEzbEdlWFZXTVZoUU1rZFJhemRTZVdnM05qaFZOa3hSVFhndlduaEVVek5hY0V0U1FWTjFVRXBGTUUxWFVWcHpiM2gxVVZGc2FIaHBWa2gwWTFkR2RYaFFaVnAwZDFCNE1IRk5WRlZSYVU4eFZGIiwiMjpSRmR6MDlQQzlOYjJSMWJIVnpQanhGZUhCdmJtVnVkRDVCVVVGQ1BDOUZlSEJ2Ym1WdWRENDhMMUpUUVV0bGVWWmhiSFZsUGc9PSIsIjA6UEZKVFFVdGxlVlpoYkhWbFBqeE5iMlIxYkhWelBuUkdkMFJKVUN0RmMxbE9Zak41VEc1dVRWRkJaMmxQZFRGaE9UVTJTWGxqVURoMGRqWk1aREUxYkdodFR6VlBaRU5oVURkYVdEa3JRbmxuTlZrNE5GSnVUVEpCWlZobVdtNXlSVGx2Wlc5UVJrcExiRkl2ZURoc1dUQnpkSFJCY1ZsclNGRXhRemgxUkVweFpVTmxWR1JzWjNWd1Uya3hTM3B3TWpsVmNFVm5RbXgxVVVsNldFZGtSa0p4TUhORFpXTjNaMFV2ZDNoS1psRTNNV3RPVlhSdSJdLCJpc3MiOiJzZWxmIiwiZXhwIjoxNjg5MTU1Njk3LCJpYXQiOjE2ODkxMDE2OTd9.DDDCXhCPnP0pJYmnV4solZe8CXiXSis-VJZmGYXfpWHoYLFOdvH0ZvgIo-oZIIQBV0f3X7-yMlfhJ9s6rzI_V76cajw-sn8BCKXbwT_iAlzNimkClqFJO1TIPShiVPMjLNLHpimojc_6OvA59oxP1r26batu-TvJMuPPxTm0jzuH2cPBSgj5GF_KQ8lAuRfr9WkCBFVZEMPlp-T69lZo7YcUt4Cdj61Zaz-E6xZPp-3JsaoKp1vi7t3TEFIEHpVGfgmemay7FFKYAkzsBm7z3T6vHXB40C4fMyDsIggAf07M6-jR1yMy8nSDtVCpcwMFLbjuv6sJ5fKB04yWhiXm2g' \
   --header 'Cookie: JSESSIONID=ED68AFEBC21FF3BE5BB35FB6629AECD5' \
   --data 'eyJraWQiOiJ3YzEtand0LWRlbW8iLCJhbGciOiJSUzI1NiJ9.eyJjb21wYW55Q29kZSI6IkJPTEVSTyIsInN1YiI6IlMxNSIsImNvZGUiOiJTMTUiLCJzaWduYXR1cmUiOiJzZWVuaSIsImlzcyI6InNlbGYiLCJlYmxEb2N1bWVudElkIjoiMTIzIiwidGltZVpvbmUiOiJVSyIsImxhbmd1YWdlIjoiRU4iLCJyaWQiOiJzZWVuaW11cnVnYW4iLCJuYmYiOjE2ODkxMDE3MDEsImFjdGlvbiI6InRlc3QiLCJleHAiOjE2ODkxNTU3MDEsImlhdCI6MTY4OTEwMTcwMX0.cSsT2bfu4j2AxX2HtUE5N4cuVmbpri_YEfDv5Ins3RHFr_rT5lxFANNQmV7iUpYInwPl0WI9WQwKlmSEpGVNG1L2Iu6xUHYUAItpMvwsrrkObicpAcvVIj7eiV1YjOFF18jHStuI9iyU4vG0S3VcabIr0HtDobJ1eD_w2aX8hHSNSYAftTrjJ8MjvMjHyPkPY8AvT12usX4hnMcsMztUH4zg65xePxGGrC6TYLAbiu_kUypxVBLkVngF3oY6SkqOToIAkDt1EhFcad7u3qNryVMbE-KLj0vyyx7qSXGCkioOosSvTBTncHiy6O_WvsF0X_HLH_FaKz_Fz63zA8fUzw'


# Version:
## To use with Spring boot 2.5.14
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-jose</artifactId>
    <version>5.7.9</version>
</dependency>

