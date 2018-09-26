package org.openhab.binding.zwave.internal.protocol.commandclass.impl.security2.enums;

public enum ZWaveSecurity2DskDigitInputMethod {
    MANUAL(5),
    QR_CODE(16);

    private final int numberOfDigitsReceived;

    private ZWaveSecurity2DskDigitInputMethod(int numberOfDigitsReceived) {
        this.numberOfDigitsReceived = numberOfDigitsReceived;
    }

    protected int getNumberOfDigitsReceived() {
        return numberOfDigitsReceived;
    }
}
