package org.openhab.binding.zwave.internal.protocol.security.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;

import org.openhab.binding.zwave.internal.protocol.security.crypto.interfaces.ZWaveCryptoDiffieHellman;

/**
 * Uses default JCE provider that is JRE 8+
 *
 * @author Dave Badia
 *
 */
class ZWaveCryptoDiffieHellmanImpl implements ZWaveCryptoDiffieHellman {
    private static final String ALGORITHM_EC = "EC";

    /**
     * {@inheritDoc}
     *
     */
    @Override
    public byte[] executeDiffieHellmanKeyAgreement(ECPrivateKey ourPrivateKey, byte[] devicePublicKeyBytes,
            int nodeIdForLogging) throws ZWaveCryptoException {
        try {
            // Build public key object from bytes
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_EC);
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(devicePublicKeyBytes);
            ECPublicKey devicePublicKey = (ECPublicKey) keyFactory.generatePublic(x509KeySpec);

            // Derive the shared secret using DH key agreement
            KeyAgreement keyAgreement = KeyAgreement.getInstance(ALGORITHM_EC);
            keyAgreement.init(ourPrivateKey);
            keyAgreement.doPhase(devicePublicKey, true); // true = last phase
            byte[] sharedSecret = keyAgreement.generateSecret();
            return sharedSecret;
        } catch (RuntimeException | GeneralSecurityException e) {
            throw new ZWaveCryptoException(
                    "NODE {}: " + nodeIdForLogging + " SECURITY_2_ERR Error during ECDH key agreement", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public KeyPair generateECDHKeyPairAccordingToZwaveSpec(SecureRandom entrophySource) throws ZWaveCryptoException {
        // TODO: spec says we need to generate pub from private using EC 25519, figure out if JCE does it this way?
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM_EC);
            // TODO: use Algorithemparameters to pass our entrophySource
            keyPairGenerator.initialize(256);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new ZWaveCryptoException("Error during buildEntrophySource", e);
        }
    }

}
