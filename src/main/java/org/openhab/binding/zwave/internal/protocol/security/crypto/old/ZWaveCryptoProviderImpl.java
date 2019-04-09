package org.openhab.binding.zwave.internal.protocol.security.crypto.old;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.EntropySourceProvider;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.openhab.binding.zwave.internal.protocol.security.crypto.ZWaveCryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// TODO: delete all in this package
class ZWaveCryptoProviderImpl {
    private static final Logger logger = LoggerFactory.getLogger(ZWaveCryptoProviderImpl.class);

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

    protected ZWaveCryptoProviderImpl() throws ZWaveCryptoException {
    }

    protected int computeAesCcmOutputSize(int plaintextLength, byte[] nonce, byte[] additionalAuthenticationData) {
        // TODO: use JCA api w/provider
        // CCMParameters is deprecated
        AEADParameters params = new AEADParameters(DUMMY_AES_KEY_PARAMETER, AES_CCM_LENGTH_BITS, DUMMY_NONCE,
                additionalAuthenticationData);
        // TODO: cache the output size?
        CCMBlockCipher cipher = new CCMBlockCipher(new AESEngine());
        cipher.init(true, params);
        return cipher.getOutputSize(plaintextLength);
    }

    protected byte[] performAesCcmCrypt(boolean encrypt, byte[] inputBytes, byte[] keyBytes, byte[] nonce,
            byte[] additionalAuthenticationData) throws ZWaveCryptoException {
        // TODO: use JCA api w/provider
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

    protected SecureRandom buildAesCounterModeDeterministicRandomNumberGenerator(byte[] entrophyBytes,
            byte[] personalizationString, byte[] nonceBytes, boolean makePredictionResistant)
            throws ZWaveCryptoException {
        throw new IllegalStateException("DRBG_CTR not supported on Java 8");
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

    public static void main(String[] args) {
        try {
            byte[] nonceBytes = new byte[0];
            ZWaveCryptoBouncyCastleProvider provider = new ZWaveCryptoBouncyCastleProvider();
            final String eiStringHex = "34cbc2b217f3d907fa2ad6a0d7a813b0fda1e17fbeed94b0e0a0abfbec947146";
            final byte[] eiBytes = hexStringToByteArray(eiStringHex);
            // OurEntropySourceProvider entropySource = new OurEntropySourceProvider(eiBytes);
            final byte[] personalizationString = "PersonalizationString".getBytes(StandardCharsets.US_ASCII);
            SecureRandom drng = provider.buildAesCounterModeDeterministicRandomNumberGenerator((SecureRandom) null,
                    personalizationString, nonceBytes, false);
            final byte[] tofill = new byte[16];
            drng.nextBytes(tofill);
            System.out.println("Done " + Arrays.toString(tofill));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // TODO: delete
    public static byte[] hexStringToByteArray(final String s) {
        final int len = s.length();
        final byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

}
