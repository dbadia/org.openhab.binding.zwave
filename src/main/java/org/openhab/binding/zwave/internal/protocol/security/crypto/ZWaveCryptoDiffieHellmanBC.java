package org.openhab.binding.zwave.internal.protocol.security.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPublicKeySpec;

import javax.crypto.KeyAgreement;

import org.openhab.binding.zwave.internal.protocol.security.crypto.interfaces.ZWaveCryptoDiffieHellman;

/**
 * Java does not support ECDH Curve25519 with key agreement until Java 11; this implementation relies on
 * https://github.com/signalapp/curve25519-java
 *
 * @author Dave Badia
 *         TODO: DB delete this
 *
 */
class ZWaveCryptoDiffieHellmanBC implements ZWaveCryptoDiffieHellman {
    private static final NamedParameterSpec EC25519_SPEC = new NamedParameterSpec("X25519");

    /**
     * {@inheritDoc}
     *
     */
    @Override
    public byte[] executeDiffieHellmanKeyAgreement(PrivateKey ourPrivateKey, byte[] devicePublicKeyBytes,
            SecureRandom entrophySource) throws ZWaveCryptoException {
        try {
            // Build the public key object
            BigInteger u = new BigInteger(devicePublicKeyBytes);
            PublicKey devicePublicKey = KeyFactory.getInstance("XDH")
                    .generatePublic(new XECPublicKeySpec(EC25519_SPEC, u));

            // Execute the agreement
            KeyAgreement keyAgreement = KeyAgreement.getInstance("XDH");
            keyAgreement.init(ourPrivateKey);
            keyAgreement.doPhase(devicePublicKey, true);
            return keyAgreement.generateSecret();
        } catch (GeneralSecurityException e) {
            throw new ZWaveCryptoException("SECURITY_2_ERR Error during ECDH key agreement", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public KeyPair generateECDHKeyPairAccordingToZwaveSpec(SecureRandom entrophySource) throws ZWaveCryptoException {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("X25519");
            // equivalent to kpg.initialize(255)
            keyPairGenerator.initialize(EC25519_SPEC, entrophySource);
            // alternatively: kpg = KeyPairGenerator.getInstance("X25519")
            return keyPairGenerator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new ZWaveCryptoException("SECURITY_2_ERR Error during ECDH key pair generation", e);
        }
    }

    @Override
    public byte[] extractPublicKeyBytes(KeyPair keyPair) {
        // TODO Auto-generated method stub
        return null;
    }

}
