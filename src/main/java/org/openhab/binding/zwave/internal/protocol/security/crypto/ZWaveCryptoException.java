package org.openhab.binding.zwave.internal.protocol.security.crypto;

public class ZWaveCryptoException extends Exception {
    private static final long serialVersionUID = -2686760569555847212L;

    // TODO: zLOW make apckage protected after deleting old
    public ZWaveCryptoException(String message, Throwable t) {
        super(message, t);
    }

    public ZWaveCryptoException(String message) {
        this(message, null);
    }
}
