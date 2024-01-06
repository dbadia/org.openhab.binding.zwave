package org.openhab.binding.zwave.internal.protocol.security.crypto;

import java.security.SecureRandom;
import java.util.HexFormat;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.EntropySourceProvider;
import org.bouncycastle.crypto.prng.drbg.CTRSP800DRBG;
import org.bouncycastle.crypto.prng.drbg.SP80090DRBG;
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
public class ZWaveCryptoAesCtrDrbgBouncyCastle implements ZWaveCryptoAesCtrDrbg {
    private static final Logger logger = LoggerFactory.getLogger(ZWaveCryptoAesCtrDrbgBouncyCastle.class);
    private static final HexFormat HEX = HexFormat.of();

    @Override
    public SecureRandom buildAesCounterModeDeterministicRandomNumberGenerator(byte[] entropyInputBytes,
            boolean makePredictionResistant) throws ZWaveCryptoException {
        final boolean useDerivationFunction = false;
        final int strength = 128;
        final int returnLength = 128;
        try {
            byte[] additionalInput1 = new byte[0];
            byte[] entrophyInput = fromHex("0f65da13dca407999d4773c2b4a11d85");
            byte[] entrophyInputReseed = fromHex("1dea0a12c52bf64339dd291c80d8ca89");
            EntropySource entropySource = new MyEntropySourceProvider(entrophyInput, makePredictionResistant)
                    .get(strength);
            SP80090DRBG d = new CTRSP800DRBG(AESEngine.newInstance(), strength, strength, entropySource,
                    PRNG_PERSONALIZATION_STRING, NONCE_NONE);
            byte[] output = new byte[returnLength];
            int written = d.generate(output, additionalInput1, makePredictionResistant);
            if (written == -1) {
                // TODO: do something else?
                logger.error("Reseed required");
            }
            byte[] toReturn = output;
            if (written != returnLength) {
                logger.error("Returned less than requested.  {}", returnLength);
                toReturn = new byte[returnLength];
                System.arraycopy(output, 0, toReturn, 0, returnLength);
            }
            throw new UnsupportedOperationException("No way to  how do we return this as a SecureRandom?");
        } catch (RuntimeException e) {
            throw new ZWaveCryptoRuntimeException("Error during init of SecureRandom DRBG", e);
        }
    }

    @Override
    public SecureRandom buildAesCounterModeDeterministicRandomNumberGenerator(SecureRandom entropyRandom,
            boolean makePredictionResistant) {
        // TODO Auto-generated method stub
        return null;
    }

    // private final static class OurEntropySource implements sun.security.provider.EntropySource {
    // private final byte[] entropyInputBytes;
    //
    // public OurEntropySource(byte[] entropyInputBytes) {
    // super();
    // this.entropyInputBytes = entropyInputBytes;
    // }
    //
    // @Override
    // public byte[] getEntropy(final int minEntropy, final int minLength, final int maxLength, final boolean pr) {
    // return entropyInputBytes;
    // }
    // }

    static byte[] fromHex(String hexString) {
        return HEX.parseHex(hexString);
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
