package org.openhab.binding.zwave.internal.protocol.security.enums;

/**
 * TODO: DOC why do we need this?
 * 
 * @author Dave Badia
 *
 */
public interface ZWaveS2BitmaskEnumType {
    // Ideally this wouldn't be public, but we have no choice since this is implemented by enum
    public int getBitPosition();
}
