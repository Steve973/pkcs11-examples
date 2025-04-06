package com.example.util;

import lombok.NoArgsConstructor;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

@NoArgsConstructor
public class TestSystemWrapper extends RestrictiveBaseSystemWrapper implements SystemWrapperApi {

    /**
     * Constructs a new instance of TestSystemWrapper with the provided properties and environment variables.
     *
     * @param properties properties to add
     * @param env environment variables to add
     */
    public TestSystemWrapper(final Map<String, String> properties, final Map<String, String> env) {
        this.properties.putAll(properties);
        this.env.putAll(env);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setProperty(String key, String value) {
        properties.put(key, value);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setEnv(String key, String value) {
        env.put(key, value);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setProperties(Map<String, String> properties) {
        Map<String, String> propertiesUpdateMap = new HashMap<>(properties);
        propertiesUpdateMap.remove(null);
        this.properties.putAll(propertiesUpdateMap);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setEnv(Map<String, String> envs) {
        Map<String, String> envUpdateMap = new HashMap<>(envs);
        envUpdateMap.remove(null);
        envUpdateMap.remove("");
        this.env.putAll(envUpdateMap);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void clearProperty(String key) {
        if (key != null && !key.isEmpty()) {
            this.properties.put(key, null);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void clearProperties(Collection<String> properties) {
        if (properties == null || properties.isEmpty()) {
            return;
        }
        System.getProperties()
                .keySet()
                .stream()
                .filter(p -> p instanceof String)
                .map(String.class::cast)
                .filter(properties::contains)
                .forEach(p -> this.properties.put(p, null));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void clearProperties() {
        System.getProperties()
                .keySet()
                .stream()
                .filter(p -> p instanceof String)
                .map(String.class::cast)
                .forEach(p -> this.properties.put(p, null));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void resetProperty(String key) {
        if (key != null && !key.isEmpty()) {
            this.properties.remove(key);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void resetProperties(Collection<String> properties) {
        if (properties == null || properties.isEmpty()) {
            return;
        }
        properties.stream()
                .filter(p -> p != null && !p.isEmpty())
                .forEach(this.properties::remove);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void resetProperties() {
        this.properties.clear();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void clearEnv(String key) {
        if (key != null && !key.isEmpty()) {
            this.env.put(key, null);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void clearEnv(Collection<String> envVars) {
        if (envVars == null || envVars.isEmpty()) {
            return;
        }
        System.getenv()
                .keySet()
                .stream()
                .filter(envVars::contains)
                .forEach(p -> this.env.put(p, null));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void clearEnv() {
        System.getenv()
                .keySet()
                .forEach(p -> this.env.put(p, null));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void resetEnv(String key) {
        if (key != null && !key.isEmpty()) {
            this.env.remove(key);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void resetEnv(Collection<String> envVars) {
        if (envVars == null || envVars.isEmpty()) {
            return;
        }
        envVars.stream()
                .filter(e -> e != null && !e.isEmpty())
                .forEach(this.env::remove);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void resetEnv() {
        this.env.clear();
    }
}