package org.openhab.binding.zwave.internal.protocol.commandclass.impl.security2.enums;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Defined in 3.6.5.3.3.1 Valid Extensions and Encrypted Extensions
 */
public enum ZWaveSecurity2EncapsulationExtensionType {
    SPAN(0x01, false, true),
    MPAN(0x02, true, true),
    MGRP(0x03, false, true),
    MOS(0x04, false, false);

    private static final Map<Integer, ZWaveSecurity2EncapsulationExtensionType> LOOKUP_TABLE = new ConcurrentHashMap<>();

    private final int bitPosition;
    /**
     * 3.6.5.3.3.1 Valid Extensions and Encrypted Extensions - Table 12
     */
    private final boolean encrypted;
    private final boolean critical;

    private ZWaveSecurity2EncapsulationExtensionType(int bitPosition, boolean encrypted, boolean critical) {
        this.bitPosition = bitPosition;
        this.encrypted = encrypted;
        this.critical = critical;
    }

    public static ZWaveSecurity2EncapsulationExtensionType parse(int data) {
        if (LOOKUP_TABLE.isEmpty()) {
            for (ZWaveSecurity2EncapsulationExtensionType type : ZWaveSecurity2EncapsulationExtensionType.values()) {
                LOOKUP_TABLE.put(type.bitPosition, type);
            }
        }
        return LOOKUP_TABLE.get(data);
    }

    public boolean isEncrypted() {
        return encrypted;
    }

    public byte asByte() {
        return (byte) bitPosition;
    }

    public boolean isCritical() {
        return critical;
    }
}
