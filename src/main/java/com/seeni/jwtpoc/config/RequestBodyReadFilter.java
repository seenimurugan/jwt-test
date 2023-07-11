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

import static org.springframework.web.bind.annotation.RequestMethod.POST;

@Component
@Slf4j
@RequiredArgsConstructor
public class RequestBodyReadFilter extends OncePerRequestFilter {

    public static final String REQUEST_BODY = "requestBody";
    private final CustomTokenValidationProperties customTokenValidationProperties;
    private final AntPathMatcher antPathMatcher;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        if (isRequestMethodMatch(request) && isRequestPathMatch(request)) {
            var requestBody = request.getReader()
                    .lines()
                    .collect(Collectors.joining(System.lineSeparator()));
            request.setAttribute(REQUEST_BODY, requestBody);
        }

        filterChain.doFilter(request, response);
    }

    private boolean isRequestMethodMatch(HttpServletRequest request) {
        return POST.name().equalsIgnoreCase(request.getMethod());
    }

    private boolean isRequestPathMatch(HttpServletRequest request) {
        return customTokenValidationProperties.postRequestPath().stream()
                .anyMatch(pattern -> antPathMatcher.match(pattern, request.getRequestURI()));
    }
}
