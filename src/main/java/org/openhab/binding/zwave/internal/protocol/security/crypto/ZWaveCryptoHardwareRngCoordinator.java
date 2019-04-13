package org.openhab.binding.zwave.internal.protocol.security.crypto;

import java.util.concurrent.TimeUnit;

import org.openhab.binding.zwave.internal.protocol.serialmessage.GetRandomMessageClass;

public class ZWaveCryptoHardwareRngCoordinator {
    private Object lock = new Object();

    private final boolean supportsRandom;
    private boolean responseReceived;
    private ZWaveCryptoException exception;
    private byte[] randomBytes;

    public ZWaveCryptoHardwareRngCoordinator(boolean supportsRandom) {
        this.supportsRandom = supportsRandom;
    }

    public void analyzeResponse(GetRandomMessageClass controllerGetRandomProcessor) {
        synchronized (lock) {
            try {
                this.randomBytes = controllerGetRandomProcessor.getRandomBytes();
            } catch (ZWaveCryptoException e) {
                exception = e;
            }
            lock.notifyAll();
        }
    }

    public boolean isSupportsRandom() {
        return supportsRandom;
    }

    public byte[] waitForRandom(TimeUnit timeUnit, int interval) throws ZWaveCryptoException {
        long stopAt = System.currentTimeMillis() + timeUnit.toMillis(interval);
        synchronized (lock) {
            while (supportsRandom == true && (responseReceived == false || stopAt < System.currentTimeMillis())) {
                try {
                    lock.wait(System.currentTimeMillis() - stopAt);
                } catch (InterruptedException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
        }
        if (supportsRandom == false) {
            throw new ZWaveCryptoException("Controller does not support GetRandom");
        } else if (exception != null) {
            throw exception;
        } else if (randomBytes == null && System.currentTimeMillis() > stopAt) {
            throw new ZWaveCryptoException("Timed out waiting for controller GetRandom reply");
        }
        return randomBytes;
    }

}
