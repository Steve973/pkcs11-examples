package com.example.util;

import com.example.util.extension.EnableTestSystemWrapper;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.*;

@Execution(ExecutionMode.CONCURRENT)
@EnableTestSystemWrapper
public class ThreadLocalStressTest {

    private static boolean evaluateSystemWrapper() {
        SystemWrapper systemWrapper = SystemWrapperProvider.get();
        return systemWrapper instanceof TestSystemWrapper &&
                "testValue".equals(systemWrapper.getEnv("TEST_ENV"));
    }

    private static final int THREAD_POOL_SIZE = 10;
    private static final int TASK_COUNT = 100;
    private static final int GC_FREQUENCY = 20;

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

    @Test
    void threadLocalAccessTest() throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
        AtomicInteger failures = new AtomicInteger();
        
        try {
            List<CompletableFuture<Void>> futures = IntStream.range(0, TASK_COUNT)
                .mapToObj(i -> CompletableFuture.runAsync(() -> {
                    // Random delay to increase contention
                    if (i % 3 == 0) randomSleep(10);
                    
                    // Check ThreadLocal
                    if (!evaluateSystemWrapper()) {
                        failures.incrementAndGet();
                    }
                    
                    // Occasional GC
                    if (i % GC_FREQUENCY == 0) System.gc();
                }, executor))
                .toList();
            
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                .get(60, TimeUnit.SECONDS);
        } finally {
            executor.shutdown();
        }
        
        assertEquals(0, failures.get(), "All tasks should access ThreadLocal");
    }

    @Test
    void threadLocalUnderMemoryPressure() throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(10);
        AtomicInteger failures = new AtomicInteger();
        List<byte[]> memoryHog = new ArrayList<>();
        
        try {
            List<CompletableFuture<Void>> futures = IntStream.range(0, 100)
                .mapToObj(i -> CompletableFuture.runAsync(() -> {
                    for (int j = 0; j < 10; j++) {
                        try {
                            memoryHog.add(new byte[1024 * 1024]);
                            System.gc();
                            randomSleep(50);
                            
                            if (!evaluateSystemWrapper()) {
                                failures.incrementAndGet();
                            }
                        } catch (OutOfMemoryError oom) {
                            memoryHog.clear();
                            System.gc();
                        }
                    }
                }, executor))
                .toList();
            
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                .get(120, TimeUnit.SECONDS);
        } finally {
            memoryHog.clear();
            System.gc();
            executor.shutdown();
        }
        
        assertEquals(0, failures.get(), "ThreadLocal should survive memory pressure");
    }

    private void randomSleep(int maxMillis) {
        try {
            Thread.sleep(ThreadLocalRandom.current().nextInt(maxMillis));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
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
