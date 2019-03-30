package org.openhab.binding.zwave.internal.protocol.security.enums;

public enum ZWaveS2DskDigitInputMethod {
    MANUAL(5),
    QR_CODE(16);

    private final int numberOfDigitsReceived;

    private ZWaveS2DskDigitInputMethod(int numberOfDigitsReceived) {
        this.numberOfDigitsReceived = numberOfDigitsReceived;
    }

    protected int getNumberOfDigitsReceived() {
        return numberOfDigitsReceived;
    }
}
