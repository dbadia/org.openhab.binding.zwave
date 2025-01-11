package org.openhab.binding.zwave.internal.protocol.security.crypto;

import java.security.SecureRandom;

import org.openhab.binding.zwave.internal.protocol.security.crypto.interfaces.ZWaveCryptoAesCtrDrbg;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * AES CTR Debug implementation
 *
 * @author Dave Badia
 *         TODO: DB delete if not used
 *
 */
public class ZWaveCryptoAesCtrDrbgOurImpl implements ZWaveCryptoAesCtrDrbg {
    private static final Logger logger = LoggerFactory.getLogger(ZWaveCryptoAesCtrDrbgOurImpl.class);

    @Override
    public SecureRandom buildAesCounterModeDeterministicRandomNumberGenerator(byte[] entrophyBytes,
            boolean makePredictionResistant) throws ZWaveCryptoException {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public SecureRandom buildAesCounterModeDeterministicRandomNumberGenerator(SecureRandom entropyRandom,
            boolean makePredictionResistant) throws ZWaveCryptoException {
        // TODO Auto-generated method stub
        return null;
    }
}
