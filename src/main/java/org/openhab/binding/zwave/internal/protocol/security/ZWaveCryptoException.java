package org.openhab.binding.zwave.internal.protocol.security;

public class ZWaveCryptoException extends Exception {
    private static final long serialVersionUID = -2686760569555847212L;

    protected ZWaveCryptoException(String message, Throwable t) {
        super(message, t);
    }

    public ZWaveCryptoException(String message) {
        this(message, null);
    }
}
