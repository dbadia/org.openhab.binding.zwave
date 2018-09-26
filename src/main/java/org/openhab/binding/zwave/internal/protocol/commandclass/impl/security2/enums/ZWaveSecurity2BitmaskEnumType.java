package org.openhab.binding.zwave.internal.protocol.commandclass.impl.security2.enums;

/**
 * TODO: DOC why do we need this?
 * 
 * @author Dave Badia
 *
 */
public interface ZWaveSecurity2BitmaskEnumType {
    // Ideally this wouldn't be public, but we have no choice since this is implemented by enum
    public int getBitPosition();
}
