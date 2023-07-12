package com.seeni.jwtpoc.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.io.IOException;
import java.text.ParseException;
import java.util.List;
import java.util.UUID;

import static org.springframework.http.HttpMethod.*;

@EnableMethodSecurity
@EnableWebSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

    public static final String KID = "wc1-jwt-demo";
    private final JwtSigningKey jwtSigningKey;
    private final JwtConfigProperties jwtConfigProperties;
    private final RequestBodyReadFilter requestBodyReadFilter;
    private final CustomJwtAuthenticationConverter customJwtAuthenticationConverter;

    @Bean
    public InMemoryUserDetailsManager users() {
        return new InMemoryUserDetailsManager(
                User.withUsername("seeni")
                        .password("{noop}password")
                        .authorities("read")
                        .build()
        );
    }

    @Order(2)
    @Bean
    public SecurityFilterChain formAuthenticationFilterChain(HttpSecurity http) throws Exception {

        http
                .authorizeRequests()
                .antMatchers(GET, "/login").permitAll()
                .antMatchers("/form/**").authenticated()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin();
        return http.build();
    }

    @Order(1)
    @Bean
    public SecurityFilterChain basicAuthAuthenticationFilterChain(HttpSecurity http) throws Exception {

        http.requestMatchers()
                .antMatchers("/basic/auth/**", "/loginn")
                .and()
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .csrf().disable()
                .httpBasic();
        return http.build();
    }

    @Order(Ordered.HIGHEST_PRECEDENCE)
    @Bean
    public SecurityFilterChain jwtAuthenticationFilterChain(HttpSecurity http) throws Exception {

        http.requestMatchers()
                .antMatchers("/jwt/**")
                .and()
                .authorizeRequests()
                .antMatchers(POST, "/jwt/token").permitAll()
                .antMatchers(POST, "/jwt/bodytoken").permitAll()
                .antMatchers(GET, "/jwt/keys").permitAll()
                .antMatchers(GET, "/jwt/.well-known/jwks.json").permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .csrf().disable()
                .cors().and()
                .addFilterBefore(requestBodyReadFilter, UsernamePasswordAuthenticationFilter.class)
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .jwtAuthenticationConverter(customJwtAuthenticationConverter)
                        ));
        return http.build();
    }

    @SneakyThrows
    @Bean
    public JwtEncoder jwtEncoder() {
        var jwkSet = JWKSet.load(jwtSigningKey.jwk().getFile());
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwkSet.getKeyByKeyId(KID)));
        return new NimbusJwtEncoder(jwks);
    }

    @Bean
    public JWKSet jwkSet() throws ParseException, IOException {
        return JWKSet.load(jwtSigningKey.jwkSet().getFile());
    }

    @Bean
    public RSAKey customRsaKey() throws JOSEException {
        var rsaKey = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
                .keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
                .generate();
        log.info("private and public key [{}]", rsaKey);
        log.info("public key [{}]", rsaKey.toPublicJWK());
        return rsaKey;
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(jwtConfigProperties.corsAllowedOrigins());
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowedMethods(List.of("*"));
        configuration.setAllowCredentials(true);
        configuration.setExposedHeaders(List.of("Authorization"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
