package com.seeni.jwtpoc.model.request;

import java.util.Set;

public record TokenInfo(String name, Set<String> scope) {
}
