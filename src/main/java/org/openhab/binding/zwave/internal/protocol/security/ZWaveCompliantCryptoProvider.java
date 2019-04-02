package org.openhab.binding.zwave.internal.protocol.security;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;

import javax.crypto.SecretKey;

/**
 * As of this writing, OpenHAB supports JRE 8, which does not support the necessary cryptographic operations for
 * Security2
 * <p/>
 * This interface which outlines the cryptographic calls which need to be supported by the ZWave spec for the Security2
 * command class. This class is abstract instead of an interface as we want to limit the usage of this class and it's
 * methods to this package
 *
 * @see ZWaveCryptoOperations
 * @author Dave Badia
 *
 */
abstract class ZWaveCompliantCryptoProvider {

    /**
     * Create the PRNG per the following section of the spec
     *
     * CC:009F.01.00.11.016 The PRNG MUST be implemented as an AES-128 CTR_DRBG as specified in [26]. The following
     * profile MUST be used:
     * <ul>
     * <li>No derivation function</li>
     * <li>No reseeding counter</li>
     * <li>Personalization string of 0x00 repeated 32 times</li>
     * <li>Output length = 16 bytes</li>
     * <li>security_strength is not used</li>
     * </ul>
     * <p/>
     * CC:009F.01.00.11.018 The inner state of the PRNG MUST be separated from the SPAN table.
     */
    protected abstract SecureRandom buildPrngAccordingToZwaveSpec(SecureRandom entrophySource); // TODO: remove
                                                                                                // according

    /**
     * Create a SPAN NextNonce Generator per the following section of the spec
     *
     * CC:009F.01.00.11.00F The CTR_DRBG MUST be instantiated using the following profile:
     * <ul>
     * <li>a. Entropy Input = MEI (obtained with CKDF-MEI_Expand)</li>
     * <li>
     * <li>b. Personalization_String = PersonalizationString</li>
     * <li>c. Output length = 16</li>
     * <li>d. No derivation function</li>
     * <li>e. No reseeding counter</li>
     * <li>f. No Security_strength</li>
     *
     * @param entrophySource
     * @return
     */
    protected abstract SecureRandom buildSpanNextNonceGenerator(byte[] mei, byte[] personalizationString)
            throws ZWaveCryptoException;

    /**
     * The zwave spec defines the manner in which the key pair must be generated:
     * CC:009F.01.00.11.09D
     * <ul>
     * <li>The EDCH private key MUST be created from 32 random bytes, which are generated using the PRNG function
     * (3.6.4.6). The public key is calculated from the private key using Curve25519 [28]
     * </ul>
     *
     * @param secureRandom TODO
     *
     * @return a newly generated ECDH keypair
     * @throws ZWaveCryptoException if an error occurs during the operation
     */
    protected abstract KeyPair generateECDHKeyPairAccordingToZwaveSpec(SecureRandom entrophySource)
            throws ZWaveCryptoException;

    /**
     * This method should not be invoked from outside of this package, use
     * {@link #buildPrngAccordingToZwaveSpec(SecureRandom)} or {@link #buildSpanNextNonceGenerator(byte[], byte[])}
     * instead
     *
     * AES_128_CTR_DRNG is used for two different functions in the spec (CC:009F.01.00.11.016 and CC:009F.01.00.11.00F),
     * both of which specify the following:
     * No derivation function
     * No reseeding counter
     * No Security_strength
     *
     * @see {@link #buildPrngAccordingToZwaveSpec(SecureRandom)}
     * @see {@link #buildSpanNextNonceGenerator(byte[], byte[])}
     *
     *      TODO: DOC
     * @param entrophyBytes
     * @param personalizationString
     * @param nonce
     * @param makePredictionResistant
     * @return
     */
    protected abstract SecureRandom buildAesCounterModeDeterministicRandomNumberGenerator(byte[] entrophyBytes,
            byte[] personalizationString, byte[] nonce, boolean makePredictionResistant)
            throws ZWaveCryptoException;

    /**
     * TODO: doc
     *
     * @param secretKey
     * @param dataToMacArray
     * @return
     * @throws ZWaveCryptoException
     */
    protected abstract byte[] performAesCmac(SecretKey secretKey, byte[]... dataToMacArray)
            throws ZWaveCryptoException;

    /**
     * This method is not be invoked from outside of this package, use
     * {@link #buildPrngAccordingToZwaveSpec(SecureRandom)} or {@link #buildSpanNextNonceGenerator(byte[], byte[])}
     * instead
     *
     * AES_128_CTR_DRNG is used for two different functions in the spec (CC:009F.01.00.11.016 and CC:009F.01.00.11.00F),
     * both of which specify the following:
     * No derivation function
     * No reseeding counter
     * No Security_strength
     *
     * @see {@link #buildPrngAccordingToZwaveSpec(SecureRandom)}
     * @see {@link #buildSpanNextNonceGenerator(byte[], byte[])}
     *
     *      TODO: DOC
     * @param entrophyBytes
     * @param personalizationString
     * @param nonce
     * @param makePredictionResistant
     * @return
     */
    protected abstract SecureRandom buildAesCounterModeDeterministicRandomNumberGenerator(SecureRandom secureRandom,
            byte[] personalizationString, byte[] nonce, boolean makePredictionResistant)
            throws ZWaveCryptoException;

    /**
     *
     * @return the strongest possible entrophy source available, which may or may not have been from a hardware RNG
     * @throws ZWaveCryptoException if an error occurs during the operation
     */
    protected abstract SecureRandom buildEntropySourceAccordingToZwaveSpec() throws ZWaveCryptoException;

    /**
     * CC:009F.01.00.11.002
     * Implementations of the Security 2 Command Class MUST provide AES-128 cryptographic services in the following
     * modes of operation:
     * <p/>
     * AES-128 CTR_DRBG
     * The Counter mode Deterministic Random Byte Generator (CTR_DRBG) [26] is a block cipher based
     * Pseudo Random Number Generator (PRNG) that is used to create Initialization Vectors and Network Keys.
     *
     * @return the AES-128 CTR_DRBG
     * @throws ZWaveCryptoException if an error occurs during the creation
     */
    protected abstract SecureRandom buildAesCounterModeDeterministicRandomNumberGenerator()
            throws ZWaveCryptoException;

    /**
     * Executes the ECDH key agreement
     *
     * @param privateKey               the ECDH private key belonging to the OH zwave controller
     * @param deviceEcdhPublicKeyBytes the ECDH public key belonging to the device in the pairing process
     * @param nodeIdForLogging         the nodeId of the device in the pairing process
     * @return the shared secret as generated by the ECDH key exchange
     * @throws ZWaveCryptoException
     */
    protected abstract byte[] executeDiffieHellmanKeyAgreement(ECPrivateKey privateKey, byte[] deviceEcdhPublicKeyBytes,
            int nodeIdForLogging) throws ZWaveCryptoException;

    /**
     * TODO: doc
     *
     * @param secretKey
     * @param dataToMacArray
     * @return
     * @throws ZWaveCryptoException
     */
    protected abstract int computeAesCcmOutputSize(int plaintextLength, byte[] nonce,
            byte[] additionalAuthenticationData);

    /**
     * TODO: doc
     *
     * @param secretKey
     * @param dataToMacArray
     * @return
     * @throws ZWaveCryptoException
     */
    protected abstract byte[] performAesCcmCrypt(boolean encrypt, byte[] inputBytes, byte[] keyBytes, byte[] nonce,
            byte[] additionalAuthenticationData) throws ZWaveCryptoException;

}
