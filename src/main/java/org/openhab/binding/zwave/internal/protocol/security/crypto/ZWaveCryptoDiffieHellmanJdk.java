package org.openhab.binding.zwave.internal.protocol.security.crypto;

import static org.openhab.binding.zwave.handler.ZWaveControllerHandler.asHex;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.XECPrivateKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;

import javax.crypto.KeyAgreement;

import org.openhab.binding.zwave.internal.protocol.security.crypto.interfaces.ZWaveCryptoDiffieHellman;
import org.openhab.binding.zwave.internal.protocol.security.enums.ZWaveS2ECDHProfile;

/**
 * Java does not support ECDH Curve25519 with key agreement until Java 11; this implementation relies on
 * https://github.com/signalapp/curve25519-java
 *
 * @author Dave Badia
 *
 */
class ZWaveCryptoDiffieHellmanJdk implements ZWaveCryptoDiffieHellman {
    /**
     * X25519 actually seems like a better fix as it's definition is 'Generates keypairs for Diffie-Hellman key
     * agreement with Curve25519 as defined in RFC 7748.'
     * But using X25519 didn't work in our testing, XDH did. XDH is defined as a more generic 'Diffie-Hellman key
     * agreement with elliptic curves as defined in RFC 7748.'
     * TODO: DB delete this if we stay with X25519
     *
     * @see https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#keymanagerfactory-algorithms
     */
    private static final String ALGORITHM = "X25519";
    private static final NamedParameterSpec EC25519_SPEC = new NamedParameterSpec(ALGORITHM);
    private static final String XDC_X509_HEADER = "302a300506032b656e032100";

    /**
     * {@inheritDoc}
     *
     */
    @Override
    public byte[] executeDiffieHellmanKeyAgreement(PrivateKey ourPrivateKey, byte[] devicePublicKeyBytes,
            SecureRandom entrophySource) throws ZWaveCryptoException {
        try {
            if (!(ourPrivateKey instanceof XECPrivateKey)) {
                throw new ZWaveCryptoException("SECURITY_2_ERR Error during ECDH key agreement, invalid key type "
                        + Arrays.toString(ourPrivateKey.getClass().getInterfaces()));
            }
            PublicKey devicePublicKey = convertBytesToXDHPublicKey(devicePublicKeyBytes);
            // Execute the agreement
            KeyAgreement keyAgreement = KeyAgreement.getInstance(ALGORITHM);
            keyAgreement.init(ourPrivateKey);
            keyAgreement.doPhase(devicePublicKey, true);
            return keyAgreement.generateSecret();
        } catch (GeneralSecurityException e) {
            throw new ZWaveCryptoException("SECURITY_2_ERR Error during ECDH key agreement", e);
        }
    }

    public static PublicKey convertBytesToXDHPublicKey(byte[] bytesParam) throws GeneralSecurityException {
        byte[] keyBytes = bytesParam;

        if (keyBytes.length == 32) {
            // Need to add the ANS.1 X509 Header so we can parse the bytes
            String hex = HexFormat.of().formatHex(keyBytes);
            hex = XDC_X509_HEADER + hex;
            keyBytes = HexFormat.of().parseHex(hex);
        }
        KeyFactory kf1 = KeyFactory.getInstance(ALGORITHM);
        PublicKey pub1 = kf1.generatePublic(new X509EncodedKeySpec(keyBytes));
        return pub1;
    }

    @Override
    public KeyPair generateECDHKeyPairAccordingToZwaveSpec(SecureRandom entrophySource) throws ZWaveCryptoException {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("X25519");
            keyPairGenerator.initialize(EC25519_SPEC, entrophySource);
            return keyPairGenerator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new ZWaveCryptoException("SECURITY_2_ERR Error during ECDH key pair generation", e);
        }
    }

    @Override
    public byte[] extractPublicKeyBytes(KeyPair keyPair) {
        // Proper way is the parse the X509, but this uses the BC API direct
        // ASN1Sequence sequence = ASN1Sequence.getInstance(ourPk);
        // DERBitString subjectPublicKey = (DERBitString) sequence.getObjectAt(1);
        // byte[] subjectPublicKeyBytes = subjectPublicKey.getBytes();

        // TODO: DB use BC above once BC runtime issue is resolved
        // This is a hack by just taking the last 32 bytes...
        byte[] publicKeyEncoded = keyPair.getPublic().getEncoded();
        int rawPublicKeySize = ZWaveS2ECDHProfile.Curve25519.getPublicKeyLengthInBytes();
        int start = publicKeyEncoded.length - rawPublicKeySize;
        byte[] publicKeyBytes2 = Arrays.copyOfRange(publicKeyEncoded, start, start + rawPublicKeySize);
        // Another way
        start = publicKeyEncoded.length - rawPublicKeySize;
        byte[] publicKeyBytes = new byte[rawPublicKeySize];
        System.arraycopy(publicKeyEncoded, start, publicKeyBytes, 0, rawPublicKeySize);
        System.out.println(asHex(publicKeyBytes)); // TODO: DB delete
        System.out.println(asHex(publicKeyBytes2));// TODO: DB delete
        return publicKeyBytes;
    }
}
