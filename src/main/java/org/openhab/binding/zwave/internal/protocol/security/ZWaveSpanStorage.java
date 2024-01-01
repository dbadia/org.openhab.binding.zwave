package org.openhab.binding.zwave.internal.protocol.security;

import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.openhab.binding.zwave.internal.protocol.security.crypto.ZWaveCryptoRuntimeException;
import org.openhab.binding.zwave.internal.protocol.security.enums.ZWaveKeyType;

import com.google.common.collect.EvictingQueue;

public class ZWaveSpanStorage {
    /**
     * CC:009F.01.00.11.006 The Nonce length MUST be 13 bytes (N = 13 bytes)
     */
    private static final int NONCE_SIZE = 13;

    public enum Direction {
        INBOUND,
        OUTBOUND
    }

    private Map<Direction, Map<ZWaveKeyType, SecureRandom>> generatorTable = new ConcurrentHashMap<>();
    private Map<ZWaveKeyType, EvictingQueue<byte[]>> recentInboundSpanTable = new ConcurrentHashMap<>();

    public void updateGenerator(ZWaveKeyType keyType, SecureRandom newSpanGenerator, Direction direction) {
        generatorTable.computeIfAbsent(direction, v -> new ConcurrentHashMap<>()).put(keyType, newSpanGenerator);
        if (direction == Direction.INBOUND) {
            recentInboundSpanTable.put(keyType, EvictingQueue.create(5));
        }
    }

    public byte[] getNextIv(Direction direction, ZWaveKeyType keytype) {
        byte[] nonce = new byte[NONCE_SIZE];
        lookupGenerator(direction, keytype).nextBytes(nonce);
        return nonce;
    }

    public boolean doesGeneratorExist(Direction direction, ZWaveKeyType keyType) {
        Map<ZWaveKeyType, SecureRandom> keyToSpanGeneratorTable = generatorTable.get(direction);
        if (keyToSpanGeneratorTable == null) {
            return false;
        }
        return keyToSpanGeneratorTable.get(keyType) != null;
    }

    private SecureRandom lookupGenerator(Direction direction, ZWaveKeyType keyType) {
        Map<ZWaveKeyType, SecureRandom> keyToSpanGeneratorTable = generatorTable.get(direction);
        if (keyToSpanGeneratorTable == null) {
            throw new ZWaveCryptoRuntimeException("keyToSpanGeneratorTable does not exist for " + direction);
        }
        SecureRandom random = keyToSpanGeneratorTable.get(keyType);
        if (random == null) {
            throw new ZWaveCryptoRuntimeException("keyToSpanGeneratorTable does not exist for " + keyType);
        }
        return random;
    }
}
