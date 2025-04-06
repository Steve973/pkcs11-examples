package com.example.util.extension;

/**
 * This class provides an empty/default configuration for the options that the
 * {@link EnableTestSystemWrapper} annotation provides to customize the entries
 * that are initially available in the system wrapper properties and environment
 * variable overlay maps.  Normally, naming an implementation by using the term
 * "Global" is a bad practice, since it normally does not describe the intent
 * or meaning behind the implementation, but this implementation is meant to be
 * the configuration when this annotation is not present on a test class, but
 * the extension is applied globally.  In that case, the test classes will not
 * have the {@link EnableTestSystemWrapper} annotation on the class, but since
 * the extension is applied, it needs to have a configuration to process.  This
 * configuration does not apply any property entries, or environment variables,
 * and it does not reset any properties or environment variable entries after
 * each test.  This is consistent with the default configuration options in the
 * {@link EnableTestSystemWrapper} annotation.
 * <p>
 * Though this is the default for the globally-applied extension, if you have a
 * test class that needs to customize these settings, you can simply add the
 * {@link EnableTestSystemWrapper} annotation on the test class, and add the
 * necessary entries, as needed, at whichever point in the lifecycle of the test
 * that you require.
 * <p>
 * Example: If you have a test class where the methods all modify a particular
 * system property value, but you need to ensure that it is reset to an
 * expected value before each test, you can apply the
 * {@link EnableTestSystemWrapper} annotation to the test class, and specify the
 * entry to be set before each test, like this:
 * <pre>
 * {@code
 * @EnableTestSystemWrapper(
 *     beforeEachProps = @Entry(key = "test.key", value = "test.value")
 * )
 * public class ExampleTest {
 *     // your test methods here...
 * }
 * }
 * </pre>
 */
@SuppressWarnings("ClassExplicitlyAnnotation")
public class GlobalTestSystemWrapperConfig implements EnableTestSystemWrapper {

    @Override
    public Entry[] preConstructProps() {
        return new Entry[0];
    }

    @Override
    public Entry[] preConstructEnv() {
        return new Entry[0];
    }

    @Override
    public Entry[] beforeAllProps() {
        return new Entry[0];
    }

    @Override
    public Entry[] beforeAllEnv() {
        return new Entry[0];
    }

    @Override
    public Entry[] beforeEachProps() {
        return new Entry[0];
    }

    @Override
    public Entry[] beforeEachEnv() {
        return new Entry[0];
    }

    @Override
    public boolean resetPropsAfterEach() {
        return false;
    }

    @Override
    public boolean resetEnvAfterEach() {
        return false;
    }

    @Override
    public Class<EnableTestSystemWrapper> annotationType() {
        return EnableTestSystemWrapper.class;
    }
}
