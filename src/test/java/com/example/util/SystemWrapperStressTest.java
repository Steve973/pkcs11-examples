package com.example.util;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

@Execution(ExecutionMode.CONCURRENT)
class SystemWrapperStressTest {

    private static boolean evaluateSystemWrapper(String location, int instanceId) {
        SystemWrapperApi systemWrapper = SystemWrapper.get();
        System.out.printf("%s (Instance %d) in thread: %s%n",
                location, instanceId, Thread.currentThread().getName());
        return systemWrapper instanceof TestSystemWrapper &&
                "testValue".equals(SystemWrapper.getEnv("TEST_ENV"));
    }

    // Create a large ID space for tracking executions
    private static final AtomicInteger instanceCounter = new AtomicInteger();
    private final int instanceId = instanceCounter.incrementAndGet();

    @BeforeAll
    static void beforeAll() {
        System.out.println("BeforeAll in thread: " + Thread.currentThread().getName());
        assertTrue(evaluateSystemWrapper("BeforeAll", -1), "ThreadLocal should be accessible in @BeforeAll");
    }

    @BeforeEach
    void setup() {
        System.out.println("BeforeEach in thread: " + Thread.currentThread().getName());
        assertTrue(evaluateSystemWrapper("BeforeEach", instanceId), "ThreadLocal should be accessible in @BeforeEach");
    }

    @Test
    @Timeout(5) // Ensure tests don't hang
    void basicValidation() {
        assertNotNull(SystemWrapper.get());
    }

    @RepeatedTest(100)
    @Timeout(5)
    void repeatedAccess(RepetitionInfo repetitionInfo) throws InterruptedException {
        Thread.sleep(250);
        assertTrue(evaluateSystemWrapper(
                "RepeatedTest[" + repetitionInfo.getCurrentRepetition() + "]", instanceId),
                "SystemWrapper should be valid during tests");
    }

    @AfterEach
    void tearDown() {
        assertTrue(evaluateSystemWrapper("AfterEach", instanceId), "ThreadLocal should be accessible in @AfterEach");
    }

    @AfterAll
    static void afterAll() {
        System.out.println("BeforeAll in thread: " + Thread.currentThread().getName());
        assertTrue(evaluateSystemWrapper("AfterAll", -1), "ThreadLocal should be accessible in @AfterAll");
    }
}
