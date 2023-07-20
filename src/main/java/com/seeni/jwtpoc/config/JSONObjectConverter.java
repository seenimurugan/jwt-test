package com.seeni.jwtpoc.config;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.configurationprocessor.json.JSONException;
import org.springframework.boot.configurationprocessor.json.JSONObject;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;
import org.springframework.util.ResourceUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Component
@RequiredArgsConstructor
public class JSONObjectConverter implements Converter<String, JSONObject> {

    private final ResourceLoader resourceLoader;

    @Override
    public JSONObject convert(String source) {
        try {
            if (ResourceUtils.isUrl(source)) {
                var resource = resourceLoader.getResource(source);
                return new JSONObject(resource.getContentAsString(StandardCharsets.UTF_8));
            } else {
                return new JSONObject(source);
            }
        } catch (JSONException | IOException e) {
            throw new RuntimeException(e);
        }
    }
}
