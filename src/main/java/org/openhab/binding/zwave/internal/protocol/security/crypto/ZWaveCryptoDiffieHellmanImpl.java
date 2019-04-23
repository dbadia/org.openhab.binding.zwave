package org.openhab.binding.zwave.internal.protocol.security.crypto;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

import org.openhab.binding.zwave.internal.protocol.security.crypto.interfaces.ZWaveCryptoDiffieHellman;
import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;
import org.whispersystems.curve25519.SecureRandomProvider;

/**
 * Java does not support ECDH Curve25519 with key agreement until Java 11; this implementation relies on
 * https://github.com/signalapp/curve25519-java
 *
 * @author Dave Badia
 *
 */
class ZWaveCryptoDiffieHellmanImpl implements ZWaveCryptoDiffieHellman {

    /**
     * {@inheritDoc}
     *
     */
    @Override
    public byte[] executeDiffieHellmanKeyAgreement(ECPrivateKey ourPrivateKey, byte[] devicePublicKeyBytes,
            SecureRandom entrophySource) throws ZWaveCryptoException {
        try {
            WhisperSystemsSecureRandomProvider secureRandom = new WhisperSystemsSecureRandomProvider(entrophySource);
            final Curve25519 cipher = Curve25519.getInstance(Curve25519.BEST, secureRandom);
            return cipher.calculateAgreement(devicePublicKeyBytes, ourPrivateKey.getEncoded());
        } catch (RuntimeException e) {
            throw new ZWaveCryptoException("SECURITY_2_ERR Error during ECDH key agreement", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public KeyPair generateECDHKeyPairAccordingToZwaveSpec(SecureRandom entrophySource) throws ZWaveCryptoException {
        try {
            WhisperSystemsSecureRandomProvider secureRandom = new WhisperSystemsSecureRandomProvider(entrophySource);
            final Curve25519 cipher = Curve25519.getInstance(Curve25519.BEST, secureRandom);
            final Curve25519KeyPair whispherKeyPair = cipher.generateKeyPair();

            // Convert to java compatible KeyPair wrapper
            ECPrivateKey ecPrivateKey = new WhisperSystemsECPrivateKey(whispherKeyPair.getPrivateKey());
            ECPublicKey ecPublicKey = new WhisperSystemsECPublicKey(whispherKeyPair.getPublicKey());
            return new KeyPair(ecPublicKey, ecPrivateKey);
        } catch (RuntimeException e) {
            throw new ZWaveCryptoException("SECURITY_2_ERR Error during ECDH key pair generation", e);
        }
    }

    // TODO: delete
    public static void main(String[] args) {
        try {
            // // TODO: spec says we need to generate pub from private using EC 25519, figure out if JCE does it this
            // way?
            // KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM_EC);
            // // TODO: use Algorithemparameters to pass our entrophySource
            // keyPairGenerator.initialize(256);
            // KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
            // NamedParameterSpec paramSpec = new NamedParameterSpec("X25519");
            // kpg.initialize(paramSpec); // equivalent to kpg.initialize(255)
            // // alternatively: kpg = KeyPairGenerator.getInstance("X25519")
            // KeyPair keyPair = kpg.generateKeyPair();
            // System.out.println("length=" + keyPair.getPublic().getEncoded().length);

            // X9ECParameters ecP = CustomNamedCurves.getByName("curve25519");
            // ECParameterSpec ecSpec = new ECParameterSpec(ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(),
            // ecP.getSeed());
            // Provider bcProvider = new BouncyCastleProvider();
            // KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", bcProvider);
            // g.initialize(ecSpec, new SecureRandom());
            // KeyPair keyPair = g.generateKeyPair();
            // System.out.println("length=" + keyPair.getPublic().getEncoded().length);

            // final Curve25519KeyPair ours = cipher.generateKeyPair();
            // final Curve25519KeyPair thiers = cipher.generateKeyPair();
            // System.out.println(ours.getPublicKey().length);
            //
            // final byte[] ourSharedSecret = cipher.calculateAgreement(ours.getPublicKey(), thiers.getPrivateKey());
            // final byte[] theirSharedSecret = cipher.calculateAgreement(thiers.getPublicKey(), ours.getPrivateKey());
            // System.out.println(Arrays.toString(ourSharedSecret));
            // System.out.println(Arrays.toString(theirSharedSecret));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static class WhisperSystemsSecureRandomProvider implements SecureRandomProvider {
        private final SecureRandom random;

        private WhisperSystemsSecureRandomProvider(SecureRandom random) {
            this.random = random;
        }

        @Override
        public void nextBytes(byte[] toFill) {
            random.nextBytes(toFill);
        }

        @Override
        public int nextInt(int bound) {
            return random.nextInt(bound);
        }
    }

    public static class WhisperSystemsECPrivateKey implements ECPrivateKey {
        private static final long serialVersionUID = -5914471231659757300L;
        private final byte[] encoded;

        private WhisperSystemsECPrivateKey(byte[] encoded) {
            this.encoded = encoded;
        }

        @Override
        public String getAlgorithm() {
            throw new UnsupportedOperationException();
        }

        @Override
        public String getFormat() {
            throw new UnsupportedOperationException();
        }

        @Override
        public byte[] getEncoded() {
            return encoded;
        }

        @Override
        public ECParameterSpec getParams() {
            throw new UnsupportedOperationException();
        }

        @Override
        public BigInteger getS() {
            throw new UnsupportedOperationException();
        }
    }

    public static class WhisperSystemsECPublicKey implements ECPublicKey {
        private static final long serialVersionUID = 2209489332348772175L;
        private final byte[] encoded;

        private WhisperSystemsECPublicKey(byte[] encoded) {
            this.encoded = encoded;
        }

        @Override
        public String getAlgorithm() {
            throw new UnsupportedOperationException();
        }

        @Override
        public String getFormat() {
            throw new UnsupportedOperationException();
        }

        @Override
        public byte[] getEncoded() {
            return encoded;
        }

        @Override
        public ECParameterSpec getParams() {
            throw new UnsupportedOperationException();
        }

        @Override
        public ECPoint getW() {
            throw new UnsupportedOperationException();
        }
    }
}
