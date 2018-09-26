package org.openhab.binding.zwave.internal.protocol.commandclass.impl.security2.enums;

/**
 * from CC:009F.01.05.11.015
 *
 */
public enum ZWaveSecurity2KexScheme implements ZWaveSecurity2BitmaskEnumType {
    _1("KEX Scheme 1", 1);

    private final String toStringString;
    private final int bitPosition;

    private ZWaveSecurity2KexScheme(String description, int bitPosition) {
        this.toStringString = description + " " + super.toString();
        this.bitPosition = bitPosition;
    }

    @Override
    public String toString() {
        return toStringString;
    }

    @Override
    public int getBitPosition() {
        return bitPosition;
    }
}