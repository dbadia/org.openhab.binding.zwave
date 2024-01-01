package org.openhab.binding.zwave.internal.protocol.security.enums;

/**
 * from CC:009F.01.05.11.015
 *
 */
public enum ZWaveS2KexScheme implements ZWaveS2BitmaskEnumType {
    // @formatter:off
    _1("KEX Scheme 1", 1);
    // @formatter:on

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