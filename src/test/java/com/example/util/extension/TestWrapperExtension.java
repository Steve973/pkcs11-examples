package com.example.util.extension;

import com.example.util.SystemWrapperProvider;
import com.example.util.TestSystemWrapper;
import org.junit.jupiter.api.extension.*;

import java.util.Arrays;
import java.util.Optional;

public class TestWrapperExtension implements
        TestInstancePreConstructCallback, BeforeAllCallback, BeforeEachCallback, AfterEachCallback {

    private static EnableTestSystemWrapper getConfig(ExtensionContext context) {
        return Optional.ofNullable(context.getRequiredTestClass())
                .map(testClass -> testClass.getAnnotation(EnableTestSystemWrapper.class))
                .orElseThrow(() -> new IllegalStateException("EnableTestSystemWrapper annotation not found"));
    }

    private static void processConfig(EnableTestSystemWrapper.Entry[] props, EnableTestSystemWrapper.Entry[] envVars) {
        TestSystemWrapper wrapper = (TestSystemWrapper) SystemWrapperProvider.get();
        Arrays.stream(props).forEach(prop -> wrapper.setProperty(prop.key(), prop.value()));
        Arrays.stream(envVars).forEach(env -> wrapper.setEnv(env.key(), env.value()));
    }

    @Override
    public void preConstructTestInstance(TestInstanceFactoryContext factoryContext, ExtensionContext extensionContext) {
        EnableTestSystemWrapper config = getConfig(extensionContext);
        processConfig(config.preConstructProps(), config.preConstructEnv());
    }

    @Override
    public void beforeAll(ExtensionContext context) {
        EnableTestSystemWrapper config = getConfig(context);
        processConfig(config.beforeAllProps(), config.beforeAllEnv());
    }

    @Override
    public void beforeEach(ExtensionContext context) {
        EnableTestSystemWrapper config = getConfig(context);
        processConfig(config.beforeEachProps(), config.beforeEachEnv());
    }

    @Override
    public void afterEach(ExtensionContext context) {
        EnableTestSystemWrapper config = getConfig(context);
        TestSystemWrapper wrapper = (TestSystemWrapper) SystemWrapperProvider.get();
        if (config.resetPropsAfterEach()) {
            wrapper.resetProperties();
        }
        if (config.resetEnvAfterEach()) {
            wrapper.resetEnv();
        }
    }
}