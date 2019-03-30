package org.openhab.binding.zwave.internal.protocol.security;

import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.EntropySource;
import org.bouncycastle.crypto.EntropySourceProvider;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.BasicEntropySourceProvider;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class ZWaveCryptoBouncyCastleProvider extends ZWaveCryptoProviderJCEJava8 {
    private static final Logger logger = LoggerFactory.getLogger(ZWaveCryptoProviderJCEJava8.class);

    /**
     * 3.6.4.4.1 CCM profile CC:009F.01.00.11.006
     * The Length field MUST be 2 bytes long (L = 2 bytes)
     */
    private static final int AES_CCM_LENGTH_BITS = 2 * 8;
    /**
     * 3.6.4.4.1 CCM profile CC:009F.01.00.11.006
     * The Nonce length MUST be 13 bytes (N = 13 bytes)
     */
    private static final int AES_CCM_NONCE_LENGTH = 13;

    /**
     * Only used for output size computation, never used for encryption or decryption
     */
    private static final KeyParameter DUMMY_AES_KEY_PARAMETER = new KeyParameter(new byte[16]);
    /**
     * Only used for output size computation, never used for encryption or decryption
     */
    private static final byte[] DUMMY_NONCE = new byte[AES_CCM_NONCE_LENGTH];

    protected ZWaveCryptoBouncyCastleProvider() throws ZWaveCryptoException {
        super(new BouncyCastleFipsProvider());
    }

    @Override
    protected int computeAesCcmOutputSize(int plaintextLength, byte[] nonce, byte[] additionalAuthenticationData) {
        // CCMParameters is deprecated
        AEADParameters params = new AEADParameters(DUMMY_AES_KEY_PARAMETER, AES_CCM_LENGTH_BITS, DUMMY_NONCE,
                additionalAuthenticationData);
        // TODO: cache the output size?
        CCMBlockCipher cipher = new CCMBlockCipher(new AESEngine());
        cipher.init(true, params);
        return cipher.getOutputSize(plaintextLength);
    }

    @Override
    protected byte[] performAesCcmCrypt(boolean encrypt, byte[] inputBytes, byte[] keyBytes, byte[] nonce,
            byte[] additionalAuthenticationData) throws ZWaveCryptoException {
        logger.debug("performAesCcm encrypt={} inputBytes={} keyBytes={} nonce={} aad={}", encrypt,
                Arrays.toString(inputBytes), Arrays.toString(keyBytes), Arrays.toString(nonce),
                Arrays.toString(additionalAuthenticationData));

        if (nonce.length != AES_CCM_NONCE_LENGTH) {
            // The Nonce length MUST be 13 bytes (N = 13 bytes)
            throw new ZWaveCryptoException(
                    "Nonce length must be " + AES_CCM_NONCE_LENGTH + " bytes per spec but found " + nonce.length);
        }
        // CCMParameters is deprecated
        AEADParameters params = new AEADParameters(new KeyParameter(keyBytes), AES_CCM_LENGTH_BITS, nonce,
                additionalAuthenticationData);
        CCMBlockCipher cipher = new CCMBlockCipher(new AESEngine());
        cipher.init(encrypt, params);
        byte[] outputBytes = new byte[cipher.getOutputSize(inputBytes.length)];
        int outputLen = cipher.processBytes(inputBytes, 0, inputBytes.length, outputBytes, 0);
        try {
            cipher.doFinal(outputBytes, outputLen);
            logger.debug("performAesCcm complete encrypt={} inputBytes={} keyBytes={} nonce={} aad={} outputBytes={}",
                    encrypt, Arrays.toString(inputBytes), Arrays.toString(keyBytes), Arrays.toString(nonce),
                    Arrays.toString(additionalAuthenticationData), Arrays.toString(outputBytes));
            return outputBytes;
        } catch (InvalidCipherTextException | IllegalStateException e) {
            throw new ZWaveCryptoException("Error during AES CCM decryption", e);
        }
    }

    @Override
    protected SecureRandom buildAesCounterModeDeterministicRandomNumberGenerator(SecureRandom entrophySource,
            byte[] personalizationString, byte[] nonceBytes, boolean makePredictionResistant)
            throws ZWaveCryptoException {
        EntropySourceProvider entropySourceProvider = new BasicEntropySourceProvider(entrophySource, true);
        return buildAesCounterModeDeterministicRandomNumberGenerator(entropySourceProvider, personalizationString,
                nonceBytes, makePredictionResistant);
    }

    @Override
    protected SecureRandom buildAesCounterModeDeterministicRandomNumberGenerator(byte[] entrophyBytes,
            byte[] personalizationString, byte[] nonceBytes, boolean makePredictionResistant)
            throws ZWaveCryptoException {
        EntropySourceProvider entrophySourceProvider = new OurEntropySourceProvider(entrophyBytes);
        return buildAesCounterModeDeterministicRandomNumberGenerator(entrophySourceProvider, personalizationString,
                nonceBytes, makePredictionResistant);
    }

    private SecureRandom buildAesCounterModeDeterministicRandomNumberGenerator(
            EntropySourceProvider entrophySourceProvider, byte[] personalizationString, byte[] nonceBytes,
            boolean makePredictionResistant) throws ZWaveCryptoException { // TODO: remove
                                                                                    // makePredictionResistant
        // @formatter:off
        /*
         * AES_128_CTR_DRNG is used for two different functions in the spec (CC:009F.01.00.11.016 and
         * CC:009F.01.00.11.00F), both of which specify the following:
         *      No derivation function
         *      No reseeding counter
         *      No Security_strength
         */
        // @formatter:on
        boolean useReseedingCounter = false;
        FipsDRBG.Builder fipsDRBGBuilder = FipsDRBG.CTR_AES_128.fromEntropySource(entrophySourceProvider)
                .setPersonalizationString(personalizationString);
        return fipsDRBGBuilder.build(nonceBytes, useReseedingCounter);
    }

    @Override
    protected SecureRandom buildAesCounterModeDeterministicRandomNumberGenerator()
            throws ZWaveCryptoException {
        // TODO Auto-generated method stub
        return null;
    }

    private static class OurEntropySourceProvider implements EntropySourceProvider {
        private final int entrophyBitsAvailable;
        private final byte[] entrophyBytes;

        private OurEntropySourceProvider(byte[] entrophyBytes) {
            this.entrophyBytes = entrophyBytes;
            this.entrophyBitsAvailable = entrophyBytes.length * 8;
        }

        @Override
        public EntropySource get(int entrophyBitsRequested) {
            if (entrophyBitsRequested > entrophyBitsAvailable) {
                logger.warn("OurEntropySourceProvider.get called with entrophyBitsRequested={} but we only have {}",
                        entrophyBitsRequested, entrophyBitsAvailable);
            } else {
                logger.debug("OurEntropySourceProvider.get called with entrophyBitsRequested={}, available={}",
                        entrophyBitsRequested, entrophyBitsAvailable);
            }
            return new OurEntropySource(entrophyBytes);
        }
    }

    private static class OurEntropySource implements EntropySource {
        private final byte[] entrophyBytes;

        private OurEntropySource(byte[] entrophyBytes) {
            this.entrophyBytes = entrophyBytes;
        }

        @Override
        public int entropySize() {
            // in bits
            return entrophyBytes.length * 8;
        }

        @Override
        public byte[] getEntropy() {
            return entrophyBytes;
        }

        @Override
        public boolean isPredictionResistant() {
            return false;
        }

    }

}
