package org.openhab.binding.zwave.internal.protocol.commandclass.impl.security2;

import java.util.Optional;

import org.openhab.binding.zwave.internal.protocol.commandclass.impl.security2.enums.ZWaveSecurity2FailType;

public class ZWaveSecurity2ProtocolViolationException extends Exception {
    private static final long serialVersionUID = 5703756532223206490L;
    private ZWaveSecurity2FailType failType;

    public ZWaveSecurity2ProtocolViolationException(String message, Throwable cause, ZWaveSecurity2FailType failType) {
        super(message, cause);
        this.failType = failType;
    }

    public ZWaveSecurity2ProtocolViolationException(String message, ZWaveSecurity2FailType failType) {
        this(message, null, failType);
    }

    public ZWaveSecurity2ProtocolViolationException(String message) {
        this(message, null, null);
    }

    public Optional<ZWaveSecurity2FailType> getFailType() {
        return Optional.ofNullable(failType);
    }

}
