package com.example.util;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public abstract class SystemWrapper {

    /**
     * The "production" system wrapper instance.
     */
    private static final RestrictiveBaseSystemWrapper RESTRICTIVE_BASE_SYSTEM_WRAPPER = new RestrictiveBaseSystemWrapper();

    /**
     * The ThreadLocal holder of the system wrapper, which returns the production system wrapper
     * singleton instance, unless test mode is enabled, in which case it returns a test system wrapper.
     */
    private static final ThreadLocal<RestrictiveBaseSystemWrapper> instance = new InheritableThreadLocal<>() {

        @Override
        protected RestrictiveBaseSystemWrapper initialValue() {
            return isTestMode() ?
                    new TestSystemWrapper(
                            Collections.emptyMap(),
                            new HashMap<>() {{
                                put("TEST_ENV", "testValue");
                            }}) :
                    RESTRICTIVE_BASE_SYSTEM_WRAPPER;
        }

        @Override
        protected RestrictiveBaseSystemWrapper childValue(final RestrictiveBaseSystemWrapper parentValue) {
            RestrictiveBaseSystemWrapper currentInstance = instance.get();
            return isTestMode() ?
                    new TestSystemWrapper(
                            currentInstance.properties,
                            currentInstance.env) :
                    RESTRICTIVE_BASE_SYSTEM_WRAPPER;
        }
    };

    private static boolean isTestMode() {
        return testMode || Arrays.stream(Thread.currentThread().getStackTrace())
                .filter(element -> element.getClassName().startsWith("org.junit."))
                .peek(x -> testMode = true)
                .findFirst()
                .isPresent();
    }

    /**
     * The flag indicating whether the system is in test mode or not.
     */
    private static boolean testMode = false;

    /**
     * Gets the current system wrapper instance.
     *
     * @return the current system wrapper instance
     */
    public static SystemWrapperApi get() {
        return instance.get();
    }

    /**
     * Returns the production system wrapper singleton instance.
     *
     * @return the production system wrapper singleton instance
     */
    public static RestrictiveBaseSystemWrapper getProductionWrapper() {
        return RESTRICTIVE_BASE_SYSTEM_WRAPPER;
    }
    /**
     * Get the property value associated with the given key.
     *
     * @param key the key to look up in the system properties
     * @return the property value associated with the given key, or null if the property is not found
     */
    public static String getProperty(String key) {
        return get().getProperty(key);
    }

    /**
     * Get the property values associated with the given keys. If the keys collection
     * is null or empty, this method will return an empty map.  If any of the values
     * associated with the given keys are null, they will be excluded from the result
     * map. If any of the entries in the keys collection is null, it will be filtered
     * out, and not processed.
     *
     * @param keys the keys to look up in the system properties
     * @return a map containing the property values associated with the given keys
     */
    public static Map<String, String> getProperties(Collection<String> keys) {
        return get().getProperties(keys);
    }

    /**
     * Gets a map containing all system properties, where any entries that are present
     * in the system properties overlay map are overridden by that entry.  That may
     * result in the removal of that entry from the returned map if the entry value
     * is null.
     *
     * @return a map containing all system properties (modified by entries in the
     * overlay map)
     */
    public static Map<String, String> getProperties() {
        return get().getProperties();
    }

    /**
     * Set multiple properties in the system properties overlay map.
     *
     * @param properties the map of system properties to be set
     */
    public static void setProperties(Map<String, String> properties) {
        get().setProperties(properties);
    }

    /**
     * Get the environment variable value associated with the given key.
     *
     * @param key the key to look up in the environment variables
     * @return the environment variable value associated with the given key, or null if it is not found
     */
    public static String getEnv(String key) {
        return get().getEnv(key);
    }

    /**
     * Get the environment variable values associated with the given keys.  If any of the values
     * associated with the given keys are null, they will be excluded from the result
     * map. If any of the entries in the keys collection is null, it will be filtered
     * out, and not processed.
     *
     * @param keys the keys to look up in the environment variables
     * @return a map containing the environment variables and their values associated with the given keys
     */
    public static Map<String, String> getEnv(Collection<String> keys) {
        return get().getEnv(keys);
    }

    /**
     * Gets a map containing all environment variables, where any entries that are present
     * in the environment variable overlay map are overridden by that entry.  That may
     * result in the removal of that entry from the returned map if the entry value
     * is null.
     *
     * @return a map containing all environment variables (modified by entries in the
     * overlay map)
     */
    public static Map<String, String> getEnv() {
        return get().getEnv();
    }

    /**
     * Set multiple environment variables in the environment overlay map.
     *
     * @param envs the map of environment variables to be set
     */
    public static void setEnv(Map<String, String> envs) {
        get().setEnv(envs);
    }

    /**
     * Set a property in the system properties overlay map.
     *
     * @param key   the system property key to be set
     * @param value the value to be set for the system property key
     */
    public static void setProperty(String key, String value) {
        get().setProperty(key, value);
    }

    /**
     * Set an environment variable in the environment overlay map.
     *
     * @param key   the environment variable key to be set
     * @param value the value to be set for the environment variable key
     */
    public static void setEnv(String key, String value) {
        get().setEnv(key, value);
    }

    /**
     * Clears/hides a system property by setting its value to null in the system
     * properties overlay map. If this system property is present, then this entry in
     * the overlay map will hide it. You need to remove this entry from the map
     * in order to make the original system property visible again.
     *
     * @param key the system property key to be cleared
     */
    public static void clearProperty(String key) {
        get().setProperty(key, null);
    }

    /**
     * Clears/hides the present system properties (with keys matching the keys in the list)
     * by setting their values in the overlay map to null. If these system properties are
     * present, then these entries in the overlay map will hide them. You need to remove
     * these entries from the map in order to make the original system properties visible
     * again.
     *
     * @param properties the map of system properties to be cleared
     */
    public static void clearProperties(Collection<String> properties) {
        get().clearProperties(properties);
    }

    /**
     * Clears/hides all present system properties by setting their values in the overlay
     * map to null. If these system properties are present, then these entries in the
     * overlay map will hide them. You need to remove these entries from the map in order
     * to make the original system properties visible again.
     */
    public static void clearProperties() {
        get().clearProperties();
    }

    /**
     * Removes the entry in the properties overlay map, if it exists, thereby letting this entry
     * in the system become exposed, if it exists.
     *
     * @param key the system property key to be reset
     */
    public static void resetProperty(String key) {
        get().resetProperty(key);
    }

    /**
     * Removes the specified entries in the properties overlay map, if they exist, thereby letting these entries
     * in the system become exposed, if they exist.
     *
     * @param properties the keys of system properties to be cleared
     */
    public static void resetProperties(Collection<String> properties) {
        get().resetProperties(properties);
    }

    /**
     * Removes all entries in the properties overlay map, thereby letting these entries in the system
     * become exposed.
     */
    public static void resetProperties() {
        get().resetProperties();
    }

    /**
     * Clears/hides an environment variable by setting its value to null in the env
     * vars overlay map. If this environment variable is present, then this entry in
     * the overlay map will hide it. You need to remove this entry from the map
     * in order to make the original environment variable visible again.
     *
     * @param key the environment variable key to be cleared
     */
    public static void clearEnv(String key) {
        get().clearEnv(key);
    }

    /**
     * Clears/hides the present environment variables (with keys matching the keys in the list)
     * by setting their values in the overlay map to null. If these environment variables are
     * present, then these entries in the overlay map will hide them. You need to remove
     * these entries from the map in order to make the original environment variables visible
     * again.
     *
     * @param envVars the keys of environment variables to be cleared
     */
    public static void clearEnv(Collection<String> envVars) {
        get().clearEnv(envVars);
    }

    /**
     * Clears/hides all present environment variables by setting their values in the overlay
     * map to null. If these environment variables are present, then these entries in the
     * overlay map will hide them. You need to remove these entries from the map in order
     * to make the original environment variables visible again.
     */
    public static void clearEnv() {
        get().clearEnv();
    }

    /**
     * Removes the entry in the env overlay map, if it exists, thereby letting this entry
     * in the system become exposed, if it exists.
     *
     * @param key the environment variable key to be reset
     */
    public static void resetEnv(String key) {
        get().resetEnv(key);
    }

    /**
     * Removes the specified entries in the env overlay map, if they exist, thereby letting these entries
     * in the system become exposed, if they exist.
     *
     * @param envVars the map of environment variables to be reset
     */
    public static void resetEnv(Collection<String> envVars) {
        get().resetEnv(envVars);
    }

    /**
     * Removes all entries in the env overlay map, thereby letting these entries in the system
     * become exposed.
     */
    public static void resetEnv() {
        get().resetEnv();
    }
}