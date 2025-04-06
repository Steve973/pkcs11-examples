package com.example.util;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.*;

@Execution(ExecutionMode.CONCURRENT)
public class ThreadContentionThreadLocalTest {

    private static boolean evaluateSystemWrapper() {
        SystemWrapperApi systemWrapper = SystemWrapper.get();
        return systemWrapper instanceof TestSystemWrapper &&
                "testValue".equals(SystemWrapper.getEnv("TEST_ENV"));
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

    @RepeatedTest(5)
    void threadPoolOperations() throws Exception {
        ExecutorService executor = Executors.newCachedThreadPool();
        AtomicInteger failures = new AtomicInteger();

        try {
            List<CompletableFuture<Void>> tasks = IntStream.range(0, 100)
                .mapToObj(i -> CompletableFuture.runAsync(() -> {
                    // Access ThreadLocal multiple times
                    for (int j = 0; j < 10; j++) {
                        if (!evaluateSystemWrapper()) {
                            failures.incrementAndGet();
                        }
                        if (j % 3 == 0) Thread.yield();
                    }
                }, executor))
                .toList();
            
            CompletableFuture.allOf(tasks.toArray(new CompletableFuture[0]))
                .get(10, TimeUnit.SECONDS);
        } finally {
            executor.shutdown();
        }
        
        assertEquals(0, failures.get());
    }

    @RepeatedTest(3)
    void recycledThreads() throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(10);
        AtomicInteger failures = new AtomicInteger();

        try {
            List<CompletableFuture<Void>> tasks = IntStream.range(0, 100)
                .mapToObj(i -> CompletableFuture.runAsync(() -> {
                    // Multiple ThreadLocal accesses
                    for (int j = 0; j < 5; j++) {
                        if (!evaluateSystemWrapper()) {
                            failures.incrementAndGet();
                        }
                        if (j % 2 == 0) try {
                            Thread.sleep(2);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                    }
                }, executor))
                .toList();
            
            CompletableFuture.allOf(tasks.toArray(new CompletableFuture[0]))
                .get(10, TimeUnit.SECONDS);
        } finally {
            executor.shutdown();
        }
        
        assertEquals(0, failures.get());
    }

    @AfterEach
    void tearDown() {
        assertTrue(evaluateSystemWrapper(), "ThreadLocal should be accessible in @AfterEach");
    }

    @AfterAll
    static void afterAll() {
        System.out.println("BeforeAll in thread: " + Thread.currentThread().getName());
        assertTrue(evaluateSystemWrapper(), "ThreadLocal should be accessible in @AfterAll");
    }
}