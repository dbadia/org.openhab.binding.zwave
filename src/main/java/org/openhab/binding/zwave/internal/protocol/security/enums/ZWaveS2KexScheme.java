package org.openhab.binding.zwave.internal.protocol.security.enums;

/**
 * from CC:009F.01.05.11.015
 *
 */
public enum ZWaveS2KexScheme implements ZWaveS2BitmaskEnumType {
    _1("KEX Scheme 1", 1);

    private final String toStringString;
    private final int bitPosition;

    private ZWaveS2KexScheme(String description, int bitPosition) {
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