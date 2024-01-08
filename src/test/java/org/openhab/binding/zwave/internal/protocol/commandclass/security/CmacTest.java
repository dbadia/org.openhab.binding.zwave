package org.openhab.binding.zwave.internal.protocol.commandclass.security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.util.HexFormat;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.openhab.binding.zwave.internal.protocol.security.crypto.CryptoInitTestHelper;
import org.openhab.binding.zwave.internal.protocol.security.crypto.ZWaveCryptoOperations;

public class CmacTest {
    private static final HexFormat HEX = HexFormat.of();

    @Test
    public void test() throws Exception {
        CryptoInitTestHelper.initCryptoForTesting();
        // Test vector taken from
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
        byte[] keybytes = HEX.parseHex("2B7E151628AED2A6ABF7158809CF4F3C");
        byte[] plaintext = HEX.parseHex("6BC1BEE22E409F96E93D7E117393172A");
        byte[] expected = HEX.parseHex("070A16B46B4D4144F79BDD9DD04A287C");
        SecretKey key = new SecretKeySpec(keybytes, "AES");
        byte[] result = ZWaveCryptoOperations.performAesCmac(key, plaintext);
        assertArrayEquals(expected, result);
    }
}
