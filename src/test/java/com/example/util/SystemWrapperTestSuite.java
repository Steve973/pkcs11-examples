package com.example.util;

import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;

@Suite
@SelectClasses({
        SystemWrapperStressTest.class,
        MemoryPressureThreadLocalTest.class,
        ThreadContentionThreadLocalTest.class,
        ThreadLocalStressTest.class})
@Execution(ExecutionMode.CONCURRENT)
public class SystemWrapperTestSuite {
    // Suite container - the annotations do the work
}
