package org.openhab.binding.zwave.internal.protocol.security.crypto;

import java.security.SecureRandom;

import org.openhab.binding.zwave.internal.protocol.security.crypto.interfaces.ZWaveCryptoAesCtrDebug;

/**
 * Java 8 does not support AES CTR_DBRG. Bouncy Castle has an implementation, but it is FIPS compliant which is not
 * compatible (it forces a derivation function, where as the ZWave spec requires none).
 *
 * @author Dave Badia
 *
 */
public class ZWaveCryptoAesCtrDebugImpl implements ZWaveCryptoAesCtrDebug {

    protected ZWaveCryptoAesCtrDebugImpl() {
        throw new UnsupportedOperationException("Java 8 does not support AES CTR_DBRG");
    }

    @Override
    public SecureRandom buildAesCounterModeDeterministicRandomNumberGenerator(byte[] entrophyBytes,
            byte[] personalizationString, byte[] nonceBytes, boolean makePredictionResistant)
            throws ZWaveCryptoException {
        throw new UnsupportedOperationException("Java 8 does not support AES CTR_DBRG");
    }

}
