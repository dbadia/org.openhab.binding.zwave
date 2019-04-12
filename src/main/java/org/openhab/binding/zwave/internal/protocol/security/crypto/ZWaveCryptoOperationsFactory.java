package org.openhab.binding.zwave.internal.protocol.security.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import org.openhab.binding.zwave.internal.protocol.security.ZWaveSecurityNetworkKeys;
import org.openhab.binding.zwave.internal.protocol.security.crypto.interfaces.ZWaveCryptoAesAeadCcm;
import org.openhab.binding.zwave.internal.protocol.security.crypto.interfaces.ZWaveCryptoAesCmac;
import org.openhab.binding.zwave.internal.protocol.security.crypto.interfaces.ZWaveCryptoAesCtrDrbg;
import org.openhab.binding.zwave.internal.protocol.security.crypto.interfaces.ZWaveCryptoDiffieHellman;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ZWaveCryptoOperationsFactory {
    private static final Logger logger = LoggerFactory.getLogger(ZWaveCryptoOperationsFactory.class);

    // per CC:009F.01.00.11.016
    private static final byte[] PRNG_PERSONALIZATION_STRING = new byte[32];
    private static final byte[] NONCE_NONE = new byte[0];
    private static final long WAIT_FOR_STICK_ENTROPY_SECONDS = 10;

    private static final Object initLock = new Object();
    private static final Object zwaveStickRandomLock = new Object();

    private static byte[] hardwareEntropyBytes = null;
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
                try {
                    final ZWaveCryptoAesAeadCcm aeadCcmProvider = new ZWaveCryptoAesAeadCcmImpl();
                    final ZWaveCryptoAesCmac cmacProvider = new ZWaveCryptoAesCmacImpl();
                    final ZWaveCryptoAesCtrDrbg ctrDrbgProvider = new ZWaveCryptoAesCtrDrbgImpl();
                    final ZWaveCryptoDiffieHellman diffieHellmanProvider = new ZWaveCryptoDiffieHellmanImpl();
                    InitTimer timer = new InitTimer();
                    waitForHardwareBaseEntropy(timer);
                    SecureRandom prng = initPrngAccordingToZwaveSpec(ctrDrbgProvider, hardwareEntropyBytes);
                    timer.record("prng");
                    logger.debug("ZWave crypto init timings: {}", timer.toString());
                    instance = new ZWaveCryptoOperations(networkSecurityKeysFromConfig, aeadCcmProvider, cmacProvider,
                            ctrDrbgProvider, diffieHellmanProvider, prng);
                    initLock.notifyAll();
                } catch (ZWaveCryptoException | RuntimeException e) {
                    throw new ZWaveCryptoRuntimeException("Error during crypto init", e);
                }
            }
        }
    }

    /**
     * CC:009F.01.00.11.017 The entropy_input [26] for instantiating the PRNG MUST be generated by a truly random
     * source, e.g. white radio noise. The PRNG MUST be hardware seeded.
     *
     * @param timer
     *
     * @return
     */
    private static void waitForHardwareBaseEntropy(InitTimer timer) {
        long stopWaitingAt = System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.toSeconds(WAIT_FOR_STICK_ENTROPY_SECONDS);
        synchronized (zwaveStickRandomLock) {
            while (hardwareEntropyBytes != null || System.currentTimeMillis() > stopWaitingAt) {
                try {
                    zwaveStickRandomLock.wait(stopWaitingAt - System.currentTimeMillis());
                } catch (InterruptedException e) {
                    // ignored
                }
            }
            if (hardwareEntropyBytes != null) {
                timer.record("zwaveStickEntropy");
                return;
            } else {
                // The stick doesn't support the random command, call SecureRandom instead
                // SPEC_VIOLATION This is currently out of compliance with the zwave spec as it requires a hardware
                // source of entropy. See CC:009F.01.00.11.017
                try {
                    timer.reset();
                    hardwareEntropyBytes = new byte[32];
                    SecureRandom.getInstanceStrong().nextBytes(hardwareEntropyBytes);
                    timer.record("getInstanceStrong");
                } catch (NoSuchAlgorithmException e) {
                    throw new ZWaveCryptoRuntimeException("Error during init of SecureRandom.getInstanceStrong()", e);
                }
            }
        }
    }

    /**
     * Initializes the PRNG per CC:009F.01.00.11.016 of the spec
     *
     * CC:009F.01.00.11.016 The PRNG MUST be implemented as an AES-128 CTR_DRBG as specified in [26]. The following
     * profile MUST be used:
     * <ul>
     * <li>No derivation function</li>
     * <li>No reseeding counter</li>
     * <li>Personalization string of 0x00 repeated 32 times</li>
     * <li>Output length = 16 bytes</li>
     * <li>security_strength is not used</li>
     * </ul>
     * <p/>
     * CC:009F.01.00.11.018 The inner state of the PRNG MUST be separated from the SPAN table.
     *
     * The entropy_input [26] for instantiating the PRNG MUST be generated by a truly random source, e.g. white radio
     * noise. The PRNG MUST be hardware seeded.
     *
     * @param ctrDrbgProvider
     */
    private static final SecureRandom initPrngAccordingToZwaveSpec(ZWaveCryptoAesCtrDrbg ctrDrbgProvider,
            byte[] hardwareSourcedEntrophyInput) throws ZWaveCryptoException {
        return ctrDrbgProvider.buildAesCounterModeDeterministicRandomNumberGenerator(hardwareSourcedEntrophyInput,
                PRNG_PERSONALIZATION_STRING, NONCE_NONE, true);
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

    private static class InitTimer {
        private long startTime = System.nanoTime();
        private Map<String, Long> elapsedTableMillis = new ConcurrentHashMap<>();

        private void record(String description) {
            long elaspedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime);
            startTime = System.nanoTime();
            elapsedTableMillis.put(description, elaspedMs);
        }

        public void reset() {
            startTime = System.nanoTime();
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
