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
    public SecureRandom buildAesCounterModeDeterministicRandomNumberGenerator(byte[] entropyInputBytes,
            byte[] personalizationString, byte[] nonceBytes, boolean makePredictionResistant)
            throws ZWaveCryptoException {
        final boolean useDerivationFunction = false;
        final int strength = 112; // TODO:is this right? is it ignored?
        EntropySource entropySource = new OurEntropySource(entropyInputBytes);
        final DrbgParameters.Instantiation config = DrbgParameters.instantiation(strength, Capability.NONE,
                personalizationString);
        final MoreDrbgParameters params = new MoreDrbgParameters(entropySource, "CTR_DRBG", "AES-128", nonceBytes,
                useDerivationFunction, config);
        try {
            return SecureRandom.getInstance("DRBG", params);
        } catch (NoSuchAlgorithmException e) {
            throw new ZWaveCryptoRuntimeException("Error during init of SecureRandom DRBG", e);
        }
    }

    private final static class OurEntropySource implements sun.security.provider.EntropySource {
        private final byte[] entropyInputBytes;

        public OurEntropySource(byte[] entropyInputBytes) {
            super();
            this.entropyInputBytes = entropyInputBytes;
        }

        public byte[] getEntropy(final int minEntropy, final int minLength, final int maxLength, final boolean pr) {
            return entropyInputBytes;
        }
    }
}
