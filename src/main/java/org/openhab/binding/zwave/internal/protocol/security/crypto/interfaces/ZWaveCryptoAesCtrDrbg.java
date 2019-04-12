package org.openhab.binding.zwave.internal.protocol.security.crypto.interfaces;

import java.security.SecureRandom;

import org.openhab.binding.zwave.internal.protocol.security.crypto.ZWaveCryptoException;

public interface ZWaveCryptoAesCtrDrbg {

    public SecureRandom buildAesCounterModeDeterministicRandomNumberGenerator(byte[] entrophyBytes,
            byte[] personalizationString, byte[] nonceBytes, boolean makePredictionResistant)
            throws ZWaveCryptoException;
}
