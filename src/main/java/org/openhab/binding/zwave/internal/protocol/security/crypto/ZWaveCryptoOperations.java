package org.openhab.binding.zwave.internal.protocol.security.crypto;

import static org.openhab.binding.zwave.internal.protocol.SerialMessage.bb2hex;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.util.Arrays;
import java.util.BitSet;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.openhab.binding.zwave.internal.protocol.security.ZWaveSecurityNetworkKeys;
import org.openhab.binding.zwave.internal.protocol.security.crypto.interfaces.ZWaveCryptoAesAeadCcm;
import org.openhab.binding.zwave.internal.protocol.security.crypto.interfaces.ZWaveCryptoAesCmac;
import org.openhab.binding.zwave.internal.protocol.security.crypto.interfaces.ZWaveCryptoAesCtrDrbg;
import org.openhab.binding.zwave.internal.protocol.security.crypto.interfaces.ZWaveCryptoDiffieHellman;
import org.openhab.binding.zwave.internal.protocol.security.enums.ZWaveKeyType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The cryptographic requirements for S2 are significantly more complex than S0, especially during the initial
 * handshake.
 * This class provides a simple interface to CommandClassSecurity2V1 for the execution of those cryptographic
 * operations.
 * <p/>
 * Given that, as of this writing, OpenHAB supports JRE 8, some cryptographic operations are not available by default.
 * Therefore, the advanced crypto operations require different cryptographic libraries to provides the necessary
 * functionality. That abstraction is also hidden from this class as it only interfaces with a
 * {@link ZWaveCryptoProvider}
 *
 *
 * @author Dave Badia
 *
 */
public class ZWaveCryptoOperations {
    private static final Logger logger = LoggerFactory.getLogger(ZWaveCryptoOperations.class);

    public static final byte RNG_ENTROPY_BYTE_COUNT = 32;
    public static final int NETWORK_SECURITY_AES_KEY_SIZE_IN_BITS = 128;

    /*
     * ConstNonce = 0x26 repeated 16 times
     */
    public static final byte[] CONST_NONCE_CONSTANT = new byte[16];

    /*
     * ConstEntropyInput = 0x88 repeated 15 times
     */
    public static final byte[] CONST_ENTROPHY_INPUT_CONSTANT = new byte[16];

    public static final byte[] CKDF_TEMP_EXTRACT_CONSTANT = new byte[16];

    // per CC:009F.01.00.11.00F
    private static final byte[] SPAN_PERSONALIZATION_STRING = "PersonalizationString".getBytes(StandardCharsets.UTF_8);
    // per CC:009F.01.00.11.016
    private static final byte[] PRNG_PERSONALIZATION_STRING = new byte[32];
    private static final byte[] NONCE_NONE = new byte[0];

    /**
     * The keys used for secure message exchange after secure inclusion
     */
    private final ZWaveSecurityNetworkKeys networkSecurityKeys;

    private final ZWaveCryptoAesAeadCcm aeadCcmProvider;

    private final ZWaveCryptoAesCmac cmacProvider;

    private final ZWaveCryptoAesCtrDrbg ctrDrbgProvider;

    private final ZWaveCryptoDiffieHellman diffieHellmanProvider;

    /**
     * CC:009F.01.00.11.015 The PRNG MUST be used for:
     * <ul>
     * <li>Generating new network keys when provisioning a new network.</li>
     * <li>Generating Nonce contributions for synchronizing the SPAN with peer nodes.</li>
     */
    private final SecureRandom prng;

    static {
        byte aByte = 0x33 & 0xFF;
        Arrays.fill(CKDF_TEMP_EXTRACT_CONSTANT, aByte);

        aByte = 0x26 & 0xFF;
        Arrays.fill(CONST_NONCE_CONSTANT, aByte);

        aByte = (byte) (0x88 & 0xFF);
        Arrays.fill(CONST_ENTROPHY_INPUT_CONSTANT, aByte);
    }

    protected ZWaveCryptoOperations(ZWaveSecurityNetworkKeys networkSecurityKeys, ZWaveCryptoAesAeadCcm aeadCcmProvider,
            ZWaveCryptoAesCmac cmacProvider, ZWaveCryptoAesCtrDrbg ctrDrbgProvider,
            ZWaveCryptoDiffieHellman diffieHellmanProvider, SecureRandom prng) {
        super();
        this.networkSecurityKeys = networkSecurityKeys;
        this.aeadCcmProvider = aeadCcmProvider;
        this.cmacProvider = cmacProvider;
        this.ctrDrbgProvider = ctrDrbgProvider;
        this.diffieHellmanProvider = diffieHellmanProvider;
        this.prng = prng;
    }

    public byte[] executeDiffieHellmanKeyAgreement(ECPrivateKey privateKey, byte[] deviceEcdhPublicKeyBytes,
            int nodeIdForLogging) throws ZWaveCryptoException {
        return diffieHellmanProvider.executeDiffieHellmanKeyAgreement(privateKey, deviceEcdhPublicKeyBytes,
                nodeIdForLogging);
    }

    /**
     * CC:009F.01.00.11.09D The EDCH private key MUST be created from 32 random bytes, which are generated using the
     * PRNG function (3.6.4.6).
     */
    public KeyPair generateECDHKeyPair() throws ZWaveCryptoException {
        return diffieHellmanProvider.generateECDHKeyPairAccordingToZwaveSpec(prng);
    }

    public byte[] performAesCmac(SecretKey secretKey, byte[]... dataToMacArray) throws ZWaveCryptoException {
        return cmacProvider.performAesCmac(secretKey, dataToMacArray);
    }

    public SecretKey buildAESKey(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
    }

    public void fillFromPrng(byte[] bytes) {
        prng.nextBytes(bytes);
    }

    public byte[] decryptWithAesCcm(byte[] cipherBytes, ZWaveKeyType keyType, byte[] nonce,
            byte[] additionalAuthenticationData) throws ZWaveCryptoException {
        SecretKey key = networkSecurityKeys.getKey(keyType);
        return cryptWithAesCcm(false, cipherBytes, key, keyType.toString(), nonce, additionalAuthenticationData);
    }

    public byte[] decryptWithAesCcm(byte[] cipherBytes, SecretKey key, byte[] nonce,
            byte[] additionalAuthenticationData) throws ZWaveCryptoException {
        return cryptWithAesCcm(false, cipherBytes, key, "Temp AES CCM", nonce, additionalAuthenticationData);
    }

    public byte[] encryptWithAesCcm(byte[] plaintextBytes, ZWaveKeyType keyType, byte[] nonce,
            byte[] additionalAuthenticationData) throws ZWaveCryptoException {
        SecretKey key = networkSecurityKeys.getKey(keyType);
        return cryptWithAesCcm(true, plaintextBytes, key, keyType.toString(), nonce, additionalAuthenticationData);
    }

    public byte[] encryptWithAesCcm(byte[] plaintextBytes, SecretKey key, byte[] nonce,
            byte[] additionalAuthenticationData) throws ZWaveCryptoException {
        return cryptWithAesCcm(true, plaintextBytes, key, "Temp AES CCM", nonce, additionalAuthenticationData);
    }

    public int computeAesCcmOutputSize(int plaintextLength, byte[] nonce, byte[] additionalAuthenticationData) {
        return aeadCcmProvider.computeAesCcmOutputSize(plaintextLength, nonce, additionalAuthenticationData);
    }

    /**
     * Invoked by the public encryptWithAesCcm methods
     *
     * @param keyDescription A textual description of the key in use for debug logging
     * @return the ciphertext
     * @throws ZWaveCryptoException
     */
    private byte[] cryptWithAesCcm(boolean encrypt, byte[] inputBytes, SecretKey key, String keyDescription,
            byte[] nonce, byte[] additionalAuthenticationData) throws ZWaveCryptoException {
        byte[] keyBytes = key.getEncoded();
        if (encrypt) {
            // TODO: log remove keyBytes from the log statement
            logger.debug("encryptWithAesCcm with {} plaintextBytes={} key={} nonce={} aad={}", keyDescription,
                    bb2hex(inputBytes), bb2hex(keyBytes), bb2hex(nonce), bb2hex(additionalAuthenticationData));
        } else {
            // TODO: log remove keyBytes from the log statement
            logger.debug("encryptWithAesCcm with {} ciphertextBytes={} key={} nonce={} aad={}", keyDescription,
                    bb2hex(inputBytes), bb2hex(keyBytes), bb2hex(nonce), bb2hex(additionalAuthenticationData));
        }
        return aeadCcmProvider.performAesCcmCrypt(encrypt, inputBytes, keyBytes, nonce, additionalAuthenticationData);
    }

    /**
     * TODO: zDoc
     *
     */
    public SecureRandom instantiateSpan(byte[] senderEntrophyInput, byte[] receiverEntrophyInput)
            throws ZWaveCryptoException {
        // 3.6.4.9.1 SPAN Instantiation
        // Mix the 32 bytes EI into MEI, using CKDF-MEI-Extract and CKDF-MEI-Expand functions
        // CC:009F.01.00.11.00F The CTR_DRBG MUST be instantiated using the following profile

        // @formatter:off
        /*
         * 3.6.4.9.1.1.1 CKDF-MEI-Extract
         * CKDF-MEI-Extract(ConstNonce, SenderEI | ReceiverEI) -> NoncePRK
         *  The Input is defined by:
         *      o ConstNonce = 0x26 repeated 16 times
         *  The Output is obtained by:
         *      o NoncePRK = CMAC(ConstNonce, SenderEI | ReceiverEI)
         */
        // @formatter:on
        SecretKey constNonceKey = buildAESKey(CONST_NONCE_CONSTANT);
        byte[] noncePrk = performAesCmac(constNonceKey, senderEntrophyInput, receiverEntrophyInput);

        // @formatter:off
        /*
         * 3.6.4.9.1.1.2 CKDF-MEI-Expand
         * CKDF-MEI-Expand(NoncePRK, ConstEntropyInput) -> MEI
         *  The Input is defined by:
         *      o NoncePRK is the pseudo random value obtained in the Extract step.
         *      o ConstEntropyInput = 0x88 repeated 15 times
         *  The Output is obtained by:
         *      o T0 = ConstEntropyInput | 0x00
         *      o T1 = CMAC(NoncePRK, T0 | ConstEntropyInput | 0x01)
         *      o T2 = CMAC(NoncePRK, T1 | ConstEntropyInput | 0x02)
         *      o MEI = T1 | T2
         */
        // @formatter:om
        SecretKey noncePrkKey = buildAESKey(noncePrk);
        int constLength = CONST_ENTROPHY_INPUT_CONSTANT.length;
        byte[] T0 = new byte[constLength + 1];
        System.arraycopy(CONST_ENTROPHY_INPUT_CONSTANT, 0, T0, 0, constLength);
        T0[constLength] = 0x00;
        byte[] T1 = performAesCmac(noncePrkKey, T0, CONST_ENTROPHY_INPUT_CONSTANT, new byte[] {0x01});
        byte[] T2 = performAesCmac(noncePrkKey, T1, CONST_ENTROPHY_INPUT_CONSTANT, new byte[] {0x02});
        byte[] mei = new byte[T1.length + T2.length];
        System.arraycopy(T1, 0, mei, 0, T1.length);
        System.arraycopy(T2, 0, mei, T1.length, T2.length);
        return ctrDrbgProvider.buildAesCounterModeDeterministicRandomNumberGenerator(mei, SPAN_PERSONALIZATION_STRING, NONCE_NONE, false);
    }


    // TODO: delete
    public static void main(String[] args) {
        try {
            BitSet bitSet = new BitSet(8); // All zeros
            // Echo[0] - CC:009F.01.06.11.00D The including node MUST set this flag to ‘0’.
            // bitSet.flip(0, 7);
            // Request CSA[1] - we don't support this, so set to zero
            bitSet.set(7);
            byte[] bytes = bitSet.toByteArray();
            System.out.print(bitSet.size() + "  " + bytes.length);
            if (bytes.length == 0) {
                System.out.print(" 0");
            } else {
                System.out.print(" " + bytes[0]);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
