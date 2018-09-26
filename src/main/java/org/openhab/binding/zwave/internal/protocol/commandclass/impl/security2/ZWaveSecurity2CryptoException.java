package org.openhab.binding.zwave.internal.protocol.commandclass.impl.security2;

public class ZWaveSecurity2CryptoException extends Exception {
    private static final long serialVersionUID = -2686760569555847212L;

    protected ZWaveSecurity2CryptoException(String message, Throwable t) {
        super(message, t);
    }

    public ZWaveSecurity2CryptoException(String message) {
        this(message, null);
    }
}
