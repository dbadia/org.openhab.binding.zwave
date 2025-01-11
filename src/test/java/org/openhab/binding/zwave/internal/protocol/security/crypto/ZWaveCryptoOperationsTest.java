package org.openhab.binding.zwave.internal.protocol.security.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.HexFormat;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class ZWaveCryptoOperationsTest {
    private static final HexFormat HEX = HexFormat.of();

    @BeforeAll
    public static void beforeAll() {
        CryptoInitTestHelper.initCryptoForTesting(null, null);
    }

    @Test
    public void testComputeCmac() throws Exception {
        // Test vector taken from
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
        SecretKey key = ZWaveCryptoOperationsFactory.getCryptoProvider()
                .buildAESKeyFromBytes(HEX.parseHex("2B7E151628AED2A6ABF7158809CF4F3C"));
        byte[] plaintext = HEX.parseHex("6BC1BEE22E409F96E93D7E117393172A");
        byte[] actual = ZWaveCryptoOperations.performAesCmac(key, plaintext);
        assertEquals(16, actual.length);
        assertEquals("070A16B46B4D4144F79BDD9DD04A287C".toLowerCase(), HEX.formatHex(actual));
    }

    @Test
    public void testComputeMei() throws Exception {
        SecretKey noncePrkKey = ZWaveCryptoOperationsFactory.getCryptoProvider()
                .buildAESKeyFromBytes(HEX.parseHex("6713a485315e7960f918714a4ec0541c"));
        byte[] actual = ZWaveCryptoOperationsFactory.getCryptoProvider().computeMei(noncePrkKey);
        assertEquals("bacfa8c486ac1b6f74d0f560e647e68972b7d18d256ad7fa5552fa8a5769519d".toLowerCase(),
                HEX.formatHex(actual));
    }
}
