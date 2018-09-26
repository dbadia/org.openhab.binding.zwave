package org.openhab.binding.zwave.internal.protocol.commandclass.impl.security2.enums;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * from CC:009F.01.05.11.010
 * see Table 18, Supported ECDH Profiles
 *
 */
public enum ZWaveSecurity2ECDHProfile implements ZWaveSecurity2BitmaskEnumType {
    Curve25519(1, 32);

    private static Map<String, ZWaveSecurity2ECDHProfile> lookupTable = new ConcurrentHashMap<>();

    private final int bitPosition;
    private final int publicKeyLengthInBytes;

    public static ZWaveSecurity2ECDHProfile lookup(String requestedKeyString) {
        return lookupTable.get(requestedKeyString);
    }

    private ZWaveSecurity2ECDHProfile(int bitPosition, int publicKeyLengthInBytes) {
        this.bitPosition = bitPosition;
        this.publicKeyLengthInBytes = publicKeyLengthInBytes;
    }

    public int getPublicKeyLengthInBytes() {
        return publicKeyLengthInBytes;
    }

    @Override
    public int getBitPosition() {
        return bitPosition;
    }
}