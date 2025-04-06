package com.example.util;

import java.util.Collection;
import java.util.Map;

public interface SystemWrapperApi {

    String PRODUCTION_ERROR_MSG = "Modifications to system properties are only allowed " +
            "in a test environment. Use @EnableTestSystemWrapper on the test class to enable system properties " +
            "or environment variable augmentation/modification.";

    /**
     * Get the property value associated with the given key.
     *
     * @param key the key to look up in the system properties
     * @return the property value associated with the given key, or null if the property is not found
     */
    String getProperty(String key);

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
    Map<String, String> getProperties(Collection<String> keys);

    /**
     * Gets a map containing all system properties, where any entries that are present
     * in the system properties overlay map are overridden by that entry.  That may
     * result in the removal of that entry from the returned map if the entry value
     * is null.
     *
     * @return a map containing all system properties (modified by entries in the
     * overlay map)
     */
    Map<String, String> getProperties();

    /**
     * Set multiple properties in the system properties overlay map.
     *
     * @param properties the map of system properties to be set
     */
    default void setProperties(Map<String, String> properties) {
        throw new UnsupportedOperationException(PRODUCTION_ERROR_MSG);
    }

    /**
     * Get the environment variable value associated with the given key.
     *
     * @param key the key to look up in the environment variables
     * @return the environment variable value associated with the given key, or null if it is not found
     */
    String getEnv(String key);

    /**
     * Get the environment variable values associated with the given keys.  If any of the values
     * associated with the given keys are null, they will be excluded from the result
     * map. If any of the entries in the keys collection is null, it will be filtered
     * out, and not processed.
     *
     * @param keys the keys to look up in the environment variables
     * @return a map containing the environment variables and their values associated with the given keys
     */
    Map<String, String> getEnv(Collection<String> keys);

    /**
     * Gets a map containing all environment variables, where any entries that are present
     * in the environment variable overlay map are overridden by that entry.  That may
     * result in the removal of that entry from the returned map if the entry value
     * is null.
     *
     * @return a map containing all environment variables (modified by entries in the
     * overlay map)
     */
    Map<String, String> getEnv();

    /**
     * Set multiple environment variables in the environment overlay map.
     *
     * @param envs the map of environment variables to be set
     */
    default void setEnv(Map<String, String> envs) {
        throw new UnsupportedOperationException(PRODUCTION_ERROR_MSG);
    }

    /**
     * Set a property in the system properties overlay map.
     *
     * @param key   the system property key to be set
     * @param value the value to be set for the system property key
     */
    default void setProperty(String key, String value) {
        throw new UnsupportedOperationException(PRODUCTION_ERROR_MSG);
    }

    /**
     * Set an environment variable in the environment overlay map.
     *
     * @param key   the environment variable key to be set
     * @param value the value to be set for the environment variable key
     */
    default void setEnv(String key, String value) {
        throw new UnsupportedOperationException(PRODUCTION_ERROR_MSG);
    }

    /**
     * Clears/hides a system property by setting its value to null in the system
     * properties overlay map. If this system property is present, then this entry in
     * the overlay map will hide it. You need to remove this entry from the map
     * in order to make the original system property visible again.
     *
     * @param key the system property key to be cleared
     */
    default void clearProperty(String key) {
        throw new UnsupportedOperationException(PRODUCTION_ERROR_MSG);
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
    default void clearProperties(Collection<String> properties) {
        throw new UnsupportedOperationException(PRODUCTION_ERROR_MSG);
    }

    /**
     * Clears/hides all present system properties by setting their values in the overlay
     * map to null. If these system properties are present, then these entries in the
     * overlay map will hide them. You need to remove these entries from the map in order
     * to make the original system properties visible again.
     */
    default void clearProperties() {
        throw new UnsupportedOperationException(PRODUCTION_ERROR_MSG);
    }

    /**
     * Removes the entry in the properties overlay map, if it exists, thereby letting this entry
     * in the system become exposed, if it exists.
     *
     * @param key the system property key to be reset
     */
    default void resetProperty(String key) {
        throw new UnsupportedOperationException(PRODUCTION_ERROR_MSG);
    }

    /**
     * Removes the specified entries in the properties overlay map, if they exist, thereby letting these entries
     * in the system become exposed, if they exist.
     *
     * @param properties the keys of system properties to be cleared
     */
    default void resetProperties(Collection<String> properties) {
        throw new UnsupportedOperationException(PRODUCTION_ERROR_MSG);
    }

    /**
     * Removes all entries in the properties overlay map, thereby letting these entries in the system
     * become exposed.
     */
    default void resetProperties() {
        throw new UnsupportedOperationException(PRODUCTION_ERROR_MSG);
    }

    /**
     * Clears/hides an environment variable by setting its value to null in the env
     * vars overlay map. If this environment variable is present, then this entry in
     * the overlay map will hide it. You need to remove this entry from the map
     * in order to make the original environment variable visible again.
     *
     * @param key the environment variable key to be cleared
     */
    default void clearEnv(String key) {
        throw new UnsupportedOperationException(PRODUCTION_ERROR_MSG);
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
    default void clearEnv(Collection<String> envVars) {
        throw new UnsupportedOperationException(PRODUCTION_ERROR_MSG);
    }

    /**
     * Clears/hides all present environment variables by setting their values in the overlay
     * map to null. If these environment variables are present, then these entries in the
     * overlay map will hide them. You need to remove these entries from the map in order
     * to make the original environment variables visible again.
     */
    default void clearEnv() {
        throw new UnsupportedOperationException(PRODUCTION_ERROR_MSG);
    }

    /**
     * Removes the entry in the env overlay map, if it exists, thereby letting this entry
     * in the system become exposed, if it exists.
     *
     * @param key the environment variable key to be reset
     */
    default void resetEnv(String key) {
        throw new UnsupportedOperationException(PRODUCTION_ERROR_MSG);
    }

    /**
     * Removes the specified entries in the env overlay map, if they exist, thereby letting these entries
     * in the system become exposed, if they exist.
     *
     * @param envVars the map of environment variables to be reset
     */
    default void resetEnv(Collection<String> envVars) {
        throw new UnsupportedOperationException(PRODUCTION_ERROR_MSG);
    }

    /**
     * Removes all entries in the env overlay map, thereby letting these entries in the system
     * become exposed.
     */
    default void resetEnv() {
        throw new UnsupportedOperationException(PRODUCTION_ERROR_MSG);
    }
}
