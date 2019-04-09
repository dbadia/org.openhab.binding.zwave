package org.openhab.binding.zwave.internal.protocol.security;

import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.openhab.binding.zwave.internal.protocol.security.enums.ZWaveKeyType;

import com.google.common.collect.EvictingQueue;

public class ZWaveSpanStorage {
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
}
