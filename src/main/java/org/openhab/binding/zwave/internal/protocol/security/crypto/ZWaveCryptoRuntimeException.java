package org.openhab.binding.zwave.internal.protocol.security.crypto;

public class ZWaveCryptoRuntimeException extends RuntimeException {
    private static final long serialVersionUID = 2567941786693226712L;

    protected ZWaveCryptoRuntimeException(String message, Throwable t) {
        super(message, t);
    }

    public ZWaveCryptoRuntimeException(String message) {
        this(message, null);
    }
}
