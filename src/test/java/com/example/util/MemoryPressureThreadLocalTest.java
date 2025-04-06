package com.example.util;

import com.example.util.extension.EnableTestSystemWrapper;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@Execution(ExecutionMode.CONCURRENT)
@EnableTestSystemWrapper
class MemoryPressureThreadLocalTest {

    private static boolean evaluateSystemWrapper() {
        SystemWrapper systemWrapper = SystemWrapperProvider.get();
        return systemWrapper instanceof TestSystemWrapper &&
                "testValue".equals(systemWrapper.getEnv("TEST_ENV"));
    }

    @BeforeAll
    static void beforeAll() {
        System.out.println("BeforeAll in thread: " + Thread.currentThread().getName());
        assertTrue(evaluateSystemWrapper(), "ThreadLocal should be accessible in @BeforeAll");
    }

    @BeforeEach
    void setup() {
        System.out.println("BeforeEach in thread: " + Thread.currentThread().getName());
        assertTrue(evaluateSystemWrapper(), "ThreadLocal should be accessible in @BeforeEach");
    }

    @RepeatedTest(10)
    void threadLocalUnderMemoryPressure() throws Exception {
        List<byte[]> memoryHogs = new ArrayList<>();
        
        try {
            for (int i = 0; i < 50; i++) {
                // Verify ThreadLocal
                assertTrue(evaluateSystemWrapper(), "ThreadLocal should work under memory pressure");
                
                // Apply memory pressure in various ways
                if (i % 2 == 0) {
                    memoryHogs.add(new byte[1024 * 1024]); // 1MB
                } else {
                    memoryHogs.add(new byte[5 * 1024 * 1024]); // 5MB
                }
                
                // Occasional GC
                if (i % 10 == 0) {
                    System.gc();
                    Thread.sleep(20); // Allow GC time
                }
            }
        } catch (OutOfMemoryError e) {
            System.gc();
        } finally {
            memoryHogs.clear();
            System.gc();
        }

        assertTrue(evaluateSystemWrapper(), "ThreadLocal should survive extreme memory pressure");
    }

    @AfterEach
    void tearDown() {
        assertTrue(evaluateSystemWrapper(), "ThreadLocal should be valid after test");
    }

    @AfterAll
    static void afterAll() {
        System.out.println("BeforeAll in thread: " + Thread.currentThread().getName());
        assertTrue(evaluateSystemWrapper(), "ThreadLocal should be accessible in @AfterAll");
    }
}