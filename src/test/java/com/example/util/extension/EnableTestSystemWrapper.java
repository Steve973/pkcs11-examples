package com.example.util.extension;

import com.example.util.TestSystemWrapper;
import org.junit.jupiter.api.extension.ExtendWith;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation for test classes to enable the {@link TestSystemWrapper} for read/write
 * capabilities for the system wrapper.
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@ExtendWith(TestWrapperExtension.class)
public @interface EnableTestSystemWrapper {

    /**
     * Specify system properties to overlay that will be applied before the test class is instantiated.
     */
    Entry[] preConstructProps() default {};

    /**
     * Specify environment variables to overlay that will be applied before the test class is instantiated.
     */
    Entry[] preConstructEnv() default {};

    /**
     * Specify system properties to overlay that will be applied at the {@link org.junit.jupiter.api.BeforeAll} phase.
     */
    Entry[] beforeAllProps() default {};

    /**
     * Specify environment variables to overlay that will be applied at the {@link org.junit.jupiter.api.BeforeAll} phase.
     */
    Entry[] beforeAllEnv() default {};

    /**
     * Specify system properties to overlay that will be applied at the {@link org.junit.jupiter.api.BeforeEach} phase.
     */
    Entry[] beforeEachProps() default {};

    /**
     * Specify environment variables to overlay that will be applied at the {@link org.junit.jupiter.api.BeforeEach} phase.
     */
    Entry[] beforeEachEnv() default {};

    /**
     * Specify whether system properties should be reset after each test method.
     */
    boolean resetPropsAfterEach() default false;

    /**
     * Specify whether environment variables should be reset after each test method.
     */
    boolean resetEnvAfterEach() default false;

    /**
     * Specify the key and value of a system property entry or an environment variable entry
     * for injection into the test environment.
     */
    @interface Entry {
        String key();
        String value();
    }
}
