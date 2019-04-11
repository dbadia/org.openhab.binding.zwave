package org.openhab.binding.zwave.internal.protocol.security.crypto.old;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.EntropySource;
import org.bouncycastle.crypto.EntropySourceProvider;
import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.BasicEntropySourceProvider;
import org.openhab.binding.zwave.internal.protocol.security.crypto.ZWaveCryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @deprecated TODO: delete
 * @author Dave Badia
 *
 */
@Deprecated
class ZWaveCryptoBouncyCastleProvider {
    private static final Logger logger = LoggerFactory.getLogger(ZWaveCryptoBouncyCastleProvider.class);

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
    }

    protected SecureRandom buildAesCounterModeDeterministicRandomNumberGenerator(SecureRandom entrophySource,
            byte[] personalizationString, byte[] nonceBytes, boolean makePredictionResistant)
            throws ZWaveCryptoException {
        EntropySourceProvider entropySourceProvider = new BasicEntropySourceProvider(entrophySource, true);
        return buildAesCounterModeDeterministicRandomNumberGenerator(entropySourceProvider, personalizationString,
                nonceBytes, makePredictionResistant);
    }

    protected SecureRandom buildAesCounterModeDeterministicRandomNumberGenerator(byte[] entrophyBytes,
            byte[] personalizationString, byte[] nonceBytes, boolean makePredictionResistant)
            throws ZWaveCryptoException {
        EntropySourceProvider entrophySourceProvider = new OurEntropySourceProvider(entrophyBytes);
        return buildAesCounterModeDeterministicRandomNumberGenerator(entrophySourceProvider, personalizationString,
                nonceBytes, makePredictionResistant);
    }

    private SecureRandom buildAesCounterModeDeterministicRandomNumberGenerator(
            EntropySourceProvider entrophySourceProvider, byte[] personalizationString, byte[] nonceBytes,
            boolean makePredictionResistant) throws ZWaveCryptoException {
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
            OurEntropySourceProvider entropySource = new OurEntropySourceProvider(eiBytes);
            final byte[] personalizationString = "PersonalizationString".getBytes(StandardCharsets.US_ASCII);
            SecureRandom drng = provider.buildAesCounterModeDeterministicRandomNumberGenerator(entropySource,
                    personalizationString, nonceBytes, false);
            final byte[] tofill = new byte[16];
            drng.nextBytes(tofill);
            System.out.println("Done " + Arrays.toString(tofill));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected SecureRandom buildAesCounterModeDeterministicRandomNumberGenerator() throws ZWaveCryptoException {
        // TODO Auto-generated method stub
        return null;
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
