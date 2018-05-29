package com.rrtx.security.log;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LogTest {
    private static final Logger logger = LoggerFactory.getLogger(LogTest.class);

    @Test
    public void logTest(){
        logger.debug("Test log debug");
        logger.info("Test log info");
        logger.error("Test log: {} error {}", "hello", "world");
        logger.warn("Test log warn");
        logger.trace("Test log trace");
    }
}
