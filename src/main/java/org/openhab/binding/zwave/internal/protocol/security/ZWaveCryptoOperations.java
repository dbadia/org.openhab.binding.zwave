package org.openhab.binding.zwave.internal.protocol.security;

import static org.openhab.binding.zwave.internal.protocol.SerialMessage.bb2hex;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.util.BitSet;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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
    public static final int NETWORK_SECURITY_AES_KEY_SIZE_IN_BITS = 128;
    private static final Logger logger = LoggerFactory.getLogger(ZWaveCryptoOperations.class);

    /**
     * The keys used for secure message exchange after secure inclusion
     */
    private final ZWaveSecurityNetworkKeys networkSecurityKeys;

    private final ZWaveCompliantCryptoProvider zWaveComplaintCryptoProvider;

    /**
     * CC:009F.01.00.11.015 The PRNG MUST be used for:
     * <ul>
     * <li>Generating new network keys when provisioning a new network.</li>
     * <li>Generating Nonce contributions for synchronizing the SPAN with peer nodes.</li>
     */
    private final SecureRandom prng;

    protected ZWaveCryptoOperations(ZWaveCompliantCryptoProvider zWaveComplaintCryptoProvider,
            ZWaveSecurityNetworkKeys networkSecurityKeysFromConfig, SecureRandom prng) {
        this.zWaveComplaintCryptoProvider = zWaveComplaintCryptoProvider;
        this.prng = prng;
        this.networkSecurityKeys = networkSecurityKeysFromConfig;
    }

    public byte[] executeDiffieHellmanKeyAgreement(ECPrivateKey privateKey, byte[] deviceEcdhPublicKeyBytes,
            int nodeIdForLogging) throws ZWaveCryptoException {
        return zWaveComplaintCryptoProvider.executeDiffieHellmanKeyAgreement(privateKey, deviceEcdhPublicKeyBytes,
                nodeIdForLogging);
    }

    /**
     * CC:009F.01.00.11.09D The EDCH private key MUST be created from 32 random bytes, which are generated using the
     * PRNG function (3.6.4.6).
     */
    public KeyPair generateECDHKeyPair() throws ZWaveCryptoException {
        return zWaveComplaintCryptoProvider.generateECDHKeyPairAccordingToZwaveSpec(prng);
    }

    public byte[] performAesCmac(SecretKey secretKey, byte[]... dataToMacArray) throws ZWaveCryptoException {
        return zWaveComplaintCryptoProvider.performAesCmac(secretKey, dataToMacArray);
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
        return zWaveComplaintCryptoProvider.computeAesCcmOutputSize(plaintextLength, nonce,
                additionalAuthenticationData);
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
        return zWaveComplaintCryptoProvider.performAesCcmCrypt(encrypt, inputBytes, keyBytes, nonce,
                additionalAuthenticationData);
    }

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

    // TODO: delete
    // public void setKey(String networkKeyConstant, String networkKeyHex) {
    // ZWaveSecurity2KeyType keyType = ZWaveSecurity2KeyType.mapFromControllerString(networkKeyConstant);
    // if (keyType == null) {
    // logger.error("Could not map {} to a ZWaveSecurity2KeyType, key not set", networkKeyConstant);
    // return;
    // }
    // byte[] keyBytes = ZWaveSecurity0CommandClass.hexToBytes(networkKeyHex);
    // aesCcmKeyTable.put(keyType, new SecretKeySpec(keyBytes, ZWaveSecurity0CommandClass.AES));
    // }

    /*
     * This method is static as it is called from ZWaveControllerHandler which needs to execute
     * quickly. Any call to ZWaveSecurity2CryptoOperations.getInstance() will trigger entropy gathering which is quite
     * time consuming
     */
    // public static void setKeyTable(Map<ZWaveS2KeyType, String> networkKeyTable) {
    // aesCcmKeyTable = new ConcurrentHashMap<>();
    // for (Map.Entry<ZWaveS2KeyType, String> entry : networkKeyTable.entrySet()) {
    // byte[] keyBytes = ZWaveSecurity0CommandClass.hexToBytes(entry.getValue());
    // aesCcmKeyTable.put(entry.getKey(), new SecretKeySpec(keyBytes, ZWaveSecurity0CommandClass.AES));
    // }
    // }

}
