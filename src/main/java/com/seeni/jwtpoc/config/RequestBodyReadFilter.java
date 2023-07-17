package com.seeni.jwtpoc.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.stream.Collectors;

import static org.apache.commons.lang3.StringUtils.substringAfter;
import static org.apache.commons.lang3.StringUtils.substringBetween;
import static org.springframework.web.bind.annotation.RequestMethod.POST;

@Component
@Slf4j
@RequiredArgsConstructor
public class RequestBodyReadFilter extends OncePerRequestFilter {

    public static final String ACCESS_TOKEN = "access_token";
    public static final String DATA_TOKEN = "data";

    public static final String ACCESS_TOKEN_IDENTIFIER = ACCESS_TOKEN + "=";
    public static final String DATA_TOKEN_IDENTIFIER = "&" + DATA_TOKEN + "=";


    private final JwtConfigProperties jwtConfigProperties;
    private final AntPathMatcher antPathMatcher;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        if (isRequestMethodMatch(request) && isRequestPathMatch(request)) {
            var requestBody = request.getReader()
                    .lines()
                    .collect(Collectors.joining(System.lineSeparator()));
            log.debug("Request body token[{}]", requestBody);
            var accessToken = substringBetween(requestBody, ACCESS_TOKEN_IDENTIFIER, DATA_TOKEN_IDENTIFIER);
            var dataToken = substringAfter(requestBody, DATA_TOKEN_IDENTIFIER);
            request.setAttribute(ACCESS_TOKEN, accessToken);
            request.setAttribute(DATA_TOKEN, dataToken);
        }

        filterChain.doFilter(request, response);
    }

    private boolean isRequestMethodMatch(HttpServletRequest request) {
        return POST.name().equalsIgnoreCase(request.getMethod());
    }

    private boolean isRequestPathMatch(HttpServletRequest request) {
        return jwtConfigProperties.postRequestPath().stream()
                .anyMatch(pattern -> antPathMatcher.match(pattern, request.getRequestURI()));
    }
}
