package org.openhab.binding.zwave.internal.protocol.security;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.SecretKey;

import org.openhab.binding.zwave.internal.protocol.security.enums.ZWaveKeyType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ZWaveSecurityNetworkKeys {
    private static final Logger logger = LoggerFactory.getLogger(ZWaveSecurityNetworkKeys.class);

    /**
     * Start with the full list of ZWaveS2KeyType, then remove as the keys get added. What's left over is what we need
     * to generate
     */
    private List<ZWaveKeyType> keysToGenerate = null;
    private Map<ZWaveKeyType, SecretKey> keyTable = new ConcurrentHashMap<>();

    public ZWaveSecurityNetworkKeys() {
        this.keysToGenerate = Arrays.asList(ZWaveKeyType.values());
    }

    public void addKey(ZWaveKeyType keyType, SecretKey key) {
        if (keyTable.containsKey(keyType)) {
            throw new IllegalStateException("Netowrk kek " + keyType + " already exists in key table");
        }
        if (keysToGenerate.remove(keyType)) {
            throw new IllegalStateException("Programmatic error - Tried to remove networkKeyType " + keyType
                    + " but it wasn't in keysToGenerate");
        }
        keyTable.put(keyType, key);
    }

    public List<ZWaveKeyType> missingKeys() {
        return new ArrayList<>(keysToGenerate);
    }

    public SecretKey getKey(ZWaveKeyType keyType) {
        SecretKey secretKey = keyTable.get(keyType);
        if (secretKey == null) {
            throw new ZWaveCryptoRuntimeException("Network key does not exist: " + keyType);
        }
        return secretKey;
    }

}
