package org.openhab.binding.zwave.internal.protocol.security.crypto;

import java.util.concurrent.TimeUnit;

import org.openhab.binding.zwave.internal.protocol.serialmessage.GetRandomMessageClass;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Synchronizes the crypto initiation code and the gathering of entropy from the ZWave stick hardware random number
 * generator (if supported)
 *
 * @author Dave Badia
 *
 */
public class ZWaveCryptoHardwareRngCoordinator {
    private static final Logger logger = LoggerFactory.getLogger(ZWaveCryptoHardwareRngCoordinator.class);
    private Object lock = new Object();

    private final boolean supportsRandom;
    private boolean responseReceived;
    private ZWaveCryptoException exception;
    private byte[] randomBytes;

    public ZWaveCryptoHardwareRngCoordinator(boolean supportsRandom) {
        this.supportsRandom = supportsRandom;
    }

    public void analyzeResponse(GetRandomMessageClass controllerGetRandomProcessor) {
        logger.debug("hardwareRandom: analyzeResponse");
        synchronized (lock) {
            try {
                this.randomBytes = controllerGetRandomProcessor.getRandomBytes();
            } catch (ZWaveCryptoException e) {
                exception = e;
            }
            logger.debug("hardwareRandom: analyzeResponse notifyAll()");
            lock.notifyAll();
        }
    }

    public boolean isSupportsRandom() {
        return supportsRandom;
    }

    public byte[] waitForRandom(TimeUnit timeUnit, int interval) throws ZWaveCryptoException {
        long stopAt = System.currentTimeMillis() + timeUnit.toMillis(interval);
        logger.debug("waitForRandom: pre synchronized (lock) {}", Thread.currentThread().getName());
        synchronized (lock) {
            logger.debug("waitForRandom: in synchronized (lock) {}", Thread.currentThread().getName());
            while (supportsRandom == true && responseReceived == false && stopAt < System.currentTimeMillis()) {
                try {
                    logger.debug("waitForRandom: calling wait  {}", Thread.currentThread().getName());
                    lock.wait(System.currentTimeMillis() - stopAt);
                    logger.debug("waitForRandom: woke up  {}", Thread.currentThread().getName());
                } catch (InterruptedException e) {
                    // As recommended in Java Concurrency in Practice by Brian Goetz
                    Thread.currentThread().interrupt();
                }
            }
        }
        if (supportsRandom == false) {
            throw new ZWaveCryptoException("Controller does not support GetRandom");
        } else if (exception != null) {
            throw exception;
        } else if (randomBytes == null && System.currentTimeMillis() > stopAt) {
            throw new ZWaveCryptoException("Timed out waiting for controller GetRandom reply");
        } else if (randomBytes == null) {
            throw new ZWaveCryptoException("code error, randomBytes == null");
        }
        return randomBytes;
    }

}
