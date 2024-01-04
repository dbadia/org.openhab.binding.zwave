package org.openhab.binding.zwave.internal.protocol.security.crypto;

import java.security.SecureRandom;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.EntropySourceProvider;
import org.bouncycastle.crypto.prng.SP800SecureRandom;
import org.bouncycastle.crypto.prng.SP800SecureRandomBuilder;
import org.openhab.binding.zwave.internal.protocol.security.crypto.interfaces.ZWaveCryptoAesCtrDrbg;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * AES CTR Debug implementation using bouncy castle lib
 *
 * @author Dave Badia
 *         TODO: DB delete if not used
 *
 */
public class ZWaveCryptoAesCtrDrbgBouncyCastleBuilder implements ZWaveCryptoAesCtrDrbg {
    private static final Logger logger = LoggerFactory.getLogger(ZWaveCryptoAesCtrDrbgBouncyCastleBuilder.class);

    @Override
    public SecureRandom buildAesCounterModeDeterministicRandomNumberGenerator(byte[] entropyInputBytes,
            boolean makePredictionResistant) throws ZWaveCryptoException {
        final int keySizeInBits = 128;
        try {
            EntropySourceProvider entropySourceProvider = new MyEntropySourceProvider(entropyInputBytes,
                    makePredictionResistant);
            // SP800 is the NIST spec that CTR DRBG is based on
            SP800SecureRandomBuilder builder = new SP800SecureRandomBuilder(entropySourceProvider);
            SP800SecureRandom secureRandom = builder.setPersonalizationString(PRNG_PERSONALIZATION_STRING)
                    .buildCTR(AESEngine.newInstance(), keySizeInBits, NONCE_NONE, makePredictionResistant);
            return secureRandom;
        } catch (RuntimeException e) {
            throw new ZWaveCryptoRuntimeException("Error during init of SecureRandom DRBG", e);
        }
    }

    static class MyEntropySourceProvider implements EntropySourceProvider {
        private final byte[] data;
        private final boolean isPredictionResistant;

        protected MyEntropySourceProvider(byte[] data, boolean isPredictionResistant) {
            this.data = data;
            this.isPredictionResistant = isPredictionResistant;
        }

        @Override
        public EntropySource get(final int bitsRequired) {
            return new EntropySource() {
                int index = 0;

                @Override
                public boolean isPredictionResistant() {
                    return isPredictionResistant;
                }

                @Override
                public byte[] getEntropy() {
                    byte[] rv = new byte[bitsRequired / 8];
                    System.arraycopy(data, index, rv, 0, rv.length);
                    index += bitsRequired / 8;
                    return rv;
                }

                @Override
                public int entropySize() {
                    return bitsRequired;
                }
            };
        }
    }
}
