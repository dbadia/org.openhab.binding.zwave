package org.openhab.binding.zwave.internal.protocol.security;

import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ZWaveCryptoOperationsFactory {
    private static final Logger logger = LoggerFactory.getLogger(ZWaveCryptoOperationsFactory.class);

    private static final Object initLock = new Object();
    private static ZWaveCryptoOperations instance = null;

    /**
     * Initializes system crypto per the zwave spec. May be slow depending on the system to gather entropy
     */
    public static void initFromConfig(ZWaveSecurityNetworkKeys networkSecurityKeysFromConfig) {
        synchronized (initLock) {
            if (instance != null) {
                throw new ZWaveCryptoRuntimeException(
                        "ZWaveCryptoOperationsFactory.initFromConfig should only be called once");
            } else {
                InitTimer timer = new InitTimer();
                try {
                    ZWaveCompliantCryptoProvider cryptoProvider = createSecurity2CryptoProvider();
                    timer.record("provider");
                    SecureRandom entropySource = cryptoProvider.buildEntropySourceAccordingToZwaveSpec();
                    timer.record("entropy");
                    SecureRandom prng = cryptoProvider.buildPrngAccordingToZwaveSpec(entropySource);
                    timer.record("prng");
                    logger.debug("ZWave crypto init timings: {}", timer.toString());
                    instance = new ZWaveCryptoOperations(cryptoProvider, networkSecurityKeysFromConfig, prng);
                    initLock.notifyAll();
                } catch (ZWaveCryptoException | RuntimeException e) {
                    throw new ZWaveCryptoRuntimeException("Error during crypto init", e);
                }
            }
        }
    }

    /**
     * Returns the singleton instance - may block if initialization is still underway
     */
    public static ZWaveCryptoOperations getCryptoProvider() {
        synchronized (initLock) {
            while (instance == null) { // per Java Concurrency in Practice by Brian Goetz
                try {
                    initLock.wait();
                } catch (InterruptedException e) {
                    logger.debug("Caught InterruptedException while waiting for initLock, contining to wait: {}",
                            e.getMessage());
                }
            }
            return instance;
        }
    }

    /**
     * Creates the appropriate Security2Crypto provider based on the environment in which this code is running
     *
     * @return the provider
     * @throws ZWaveCryptoException if an unrecoverable error occurs during initialization
     */
    private static ZWaveCompliantCryptoProvider createSecurity2CryptoProvider() throws ZWaveCryptoException {
        return new ZWaveCryptoBouncyCastleProvider();
    }

    private static class InitTimer {
        private long startTime = System.nanoTime();
        private Map<String, Long> elapsedTableMillis = new ConcurrentHashMap<>();

        private void record(String description) {
            long elaspedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime);
            startTime = System.nanoTime();
            elapsedTableMillis.put(description, elaspedMs);
        }

        @Override
        public String toString() {
            StringBuilder buf = new StringBuilder(100);
            elapsedTableMillis.entrySet().stream()
                    .forEach(e -> buf.append(e.getKey()).append("=").append(e.getValue()).append("ms "));
            return buf.toString();
        }
    }
}
