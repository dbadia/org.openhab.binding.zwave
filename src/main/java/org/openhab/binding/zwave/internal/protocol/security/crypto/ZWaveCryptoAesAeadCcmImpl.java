package org.openhab.binding.zwave.internal.protocol.security.crypto;

import java.security.Provider;
import java.util.Arrays;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openhab.binding.zwave.internal.protocol.security.crypto.interfaces.ZWaveCryptoAesAeadCcm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * As of Java 12, the default JCE provider does not support AES CCM for some reason. So we use Bouncy Castle
 *
 * @author Dave Badia
 *
 */
class ZWaveCryptoAesAeadCcmImpl implements ZWaveCryptoAesAeadCcm {
    private static final Logger logger = LoggerFactory.getLogger(ZWaveCryptoAesAeadCcmImpl.class);

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

    private final Provider bcProvider;

    protected ZWaveCryptoAesAeadCcmImpl() {
        this.bcProvider = new BouncyCastleProvider();
    }

    @Override
    public int computeAesCcmOutputSize(int plaintextLength, byte[] nonce, byte[] additionalAuthenticationData) {
        // CCMParameters is deprecated
        AEADParameters params = new AEADParameters(DUMMY_AES_KEY_PARAMETER, AES_CCM_LENGTH_BITS, DUMMY_NONCE,
                additionalAuthenticationData);
        // TODO: cache the output size?
        CCMBlockCipher cipher = new CCMBlockCipher(new AESEngine());
        cipher.init(true, params);
        return cipher.getOutputSize(plaintextLength);
    }

    @Override
    public byte[] performAesCcmCrypt(boolean encrypt, byte[] inputBytes, byte[] keyBytes, byte[] nonce,
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

}
