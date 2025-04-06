package com.example.util;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;

public abstract class SystemWrapperProvider {

    /**
     * The "production" system wrapper instance.
     */
    private static final SystemWrapper systemWrapper = new SystemWrapper();

    /**
     * The ThreadLocal holder of the system wrapper, which returns the production system wrapper
     * singleton instance, unless test mode is enabled, in which case it returns a test system wrapper.
     */
    private static final ThreadLocal<SystemWrapper> instance = new InheritableThreadLocal<>() {

        @Override
        protected SystemWrapper initialValue() {
            return isTestMode() ?
                    new TestSystemWrapper(
                            Collections.emptyMap(),
                            new HashMap<>() {{
                                put("TEST_ENV", "testValue");
                            }}) :
                    systemWrapper;
        }

        @Override
        protected SystemWrapper childValue(final SystemWrapper parentValue) {
            SystemWrapper currentInstance = instance.get();
            return isTestMode() ?
                    new TestSystemWrapper(
                            currentInstance.properties,
                            currentInstance.env) :
                    systemWrapper;
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
    public static SystemWrapper get() {
        return instance.get();
    }

    /**
     * Returns the production system wrapper singleton instance.
     *
     * @return the production system wrapper singleton instance
     */
    public static SystemWrapper getProductionWrapper() {
        return systemWrapper;
    }
}