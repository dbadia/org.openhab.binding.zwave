package org.openhab.binding.zwave.internal.protocol.security;

import java.util.Optional;

import org.openhab.binding.zwave.internal.protocol.security.enums.ZWaveS2FailType;

public class ZWaveProtocolViolationException extends Exception {
    private static final long serialVersionUID = 5703756532223206490L;
    private ZWaveS2FailType failType;

    public ZWaveProtocolViolationException(String message, Throwable cause, ZWaveS2FailType failType) {
        super(message, cause);
        this.failType = failType;
    }

    public ZWaveProtocolViolationException(String message, ZWaveS2FailType failType) {
        this(message, null, failType);
    }

    public ZWaveProtocolViolationException(String message) {
        this(message, null, null);
    }

    public Optional<ZWaveS2FailType> getFailType() {
        return Optional.ofNullable(failType);
    }

}
