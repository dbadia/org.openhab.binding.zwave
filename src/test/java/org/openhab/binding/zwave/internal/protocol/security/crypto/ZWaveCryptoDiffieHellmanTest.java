package org.openhab.binding.zwave.internal.protocol.security.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.openhab.binding.zwave.handler.ZWaveControllerHandler.asHex;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.NamedParameterSpec;

import javax.crypto.KeyAgreement;

import org.junit.jupiter.api.Test;
import org.openhab.binding.zwave.internal.protocol.security.crypto.interfaces.ZWaveCryptoDiffieHellman;

public class ZWaveCryptoDiffieHellmanTest {
    private static final String ALGORITHM = "X25519";
    private static final NamedParameterSpec EC25519_SPEC = new NamedParameterSpec(ALGORITHM);

    @Test
    public void testKeyAgreementFrom32Bytes() throws Exception {
        // Generate two key pair
        SecureRandom sr = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("X25519");
        keyPairGenerator.initialize(EC25519_SPEC, sr);
        KeyPair ourKeyPair = keyPairGenerator.generateKeyPair();
        KeyPair deviceKeyPair = keyPairGenerator.generateKeyPair();
        // Do the key agreement with our original objects
        String generated1 = asHex(performKeyAgreementBaseline(ourKeyPair, deviceKeyPair));
        String generated2 = asHex(performKeyAgreementBaseline(deviceKeyPair, ourKeyPair));
        assertEquals(generated1, generated2);

        // Now do the same from 32 bytes
        ZWaveCryptoDiffieHellman diffieHellman = new ZWaveCryptoDiffieHellmanJdk();
        byte[] devicePublicKeyBytes32 = diffieHellman.extractPublicKeyBytes(deviceKeyPair);
        assertEquals(32, devicePublicKeyBytes32.length);
        String generated3 = asHex(
                diffieHellman.executeDiffieHellmanKeyAgreement(ourKeyPair.getPrivate(), devicePublicKeyBytes32, sr));
        assertEquals(generated1, generated3);
    }

    /**
     * Performs the key agreement with the original key objects as a baseline
     */
    private byte[] performKeyAgreementBaseline(KeyPair pairOne, KeyPair pairTwo) throws GeneralSecurityException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance(ALGORITHM);
        keyAgreement.init(pairOne.getPrivate());
        keyAgreement.doPhase(pairTwo.getPublic(), true);
        return keyAgreement.generateSecret();
    }
}
