package com.example.util;

import java.util.AbstractMap;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class RestrictiveBaseSystemWrapper implements SystemWrapperApi {

    protected final Map<String, String> properties = Collections.synchronizedMap(new HashMap<>());

    protected final Map<String, String> env = Collections.synchronizedMap(new HashMap<>());

    /**
     * {@inheritDoc}
     */
    @Override
    public String getProperty(String key) {
        return properties.containsKey(key) ? properties.get(key) : System.getProperty(key);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, String> getProperties(Collection<String> keys) {
        if (keys == null || keys.isEmpty()) {
            return Collections.emptyMap();
        }
        return keys.stream()
                .filter(Objects::nonNull)
                .map(key -> new AbstractMap.SimpleEntry<>(key, getProperty(key)))
                .filter(entry -> entry.getValue() != null)
                .distinct()
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, String> getProperties() {
        Set<String> allKeys = Stream.concat(properties.keySet().stream(), System.getProperties().keySet().stream())
                .filter(key -> key instanceof String)
                .map(String.class::cast)
                .collect(Collectors.toSet());
        return getProperties(allKeys);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getEnv(String key) {
        return env.containsKey(key) ? env.get(key) : System.getenv(key);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, String> getEnv(Collection<String> keys) {
        if (keys == null || keys.isEmpty()) {
            return Collections.emptyMap();
        }
        return keys.stream()
                .filter(Objects::nonNull)
                .map(key -> new AbstractMap.SimpleEntry<>(key, getEnv(key)))
                .filter(entry -> entry.getValue() != null)
                .distinct()
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, String> getEnv() {
        Set<String> allKeys = Stream.concat(env.keySet().stream(), System.getenv().keySet().stream())
                .collect(Collectors.toSet());
        return getProperties(allKeys);
    }
}