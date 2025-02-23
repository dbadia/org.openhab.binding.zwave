package org.openhab.binding.zwave.internal.protocol.security.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.HexFormat;

import org.junit.jupiter.api.Test;
import org.openhab.binding.zwave.internal.protocol.security.crypto.drbg.old.ZwaveCryptoCtrDebugJsPort;

public class ZWaveCryptoAesCtrDrbgImplV11Test {
    private static final HexFormat HEX = HexFormat.of();

    @Test
    public void testCtrDrbg() throws Exception {
        /*
         * 128,
         * derivation = false,
         * entropy = MEI,
         * nonce = undefined,
         * personalizationString = keys.personalizationString,
         */
        // ZWaveCryptoAesCtrDrbgOurImpl ctrDrbg = new ZWaveCryptoAesCtrDrbgOurImpl();
        byte[] entropy = HEX.parseHex("bacfa8c486ac1b6f74d0f560e647e68972b7d18d256ad7fa5552fa8a5769519d");
        byte[] personalizationString = HEX.parseHex("8bece5005a4cdcfa855d597b2590eeb38b35b2e7a90d55ca8c8a2507d4a182ff");
        // ZWaveCryptoAesCtrDrbg ctrDrbg = new ZWaveCryptoAesCtrDrbgBouncyCastleBuilder();
        // ZWaveCryptoAesCtrDrbg ctrDrbg = new ZWaveCryptoAesCtrDrbgOurImpl();
        // SecureRandom random = ctrDrbg.buildAesCounterModeDeterministicRandomNumberGenerator(entropy,
        // personalizationString, false);
        // int bits, boolean derivation, byte[] entropy, byte[] nonce, byte[] pers
        // ZwaveCryptoCtrDebug ctr = new ZwaveCryptoCtrDebug(128, false, entropy, entropy, personalizationString)
        byte[] nonce = null;
        ZwaveCryptoCtrDebugJsPort ctr = new ZwaveCryptoCtrDebugJsPort(128, false, entropy, nonce,
                personalizationString);
        byte[] bytes = new byte[13];
        // random.nextBytes(bytes);
        bytes = ctr.generate(bytes.length, null);
        assertEquals("23af81e2db91cd015abac40954".toLowerCase(), HEX.formatHex(bytes));
        // random.nextBytes(bytes);
        bytes = ctr.generate(bytes.length, null);
        assertEquals("4b2b196800b2913ef749d58972".toLowerCase(), HEX.formatHex(bytes));
    }

    @Test
    public void testCtrDrbgJsTestCaseData() throws Exception {
        // [AES-128 no df]
        // [PredictionResistance = False]
        // [EntropyInputLen = 256]
        // [NonceLen = 0]
        // [PersonalizationStringLen = 256]
        // [AdditionalInputLen = 0]
        // [ReturnedBitsLen = 512]
        //
        // COUNT = 0
        // EntropyInput = 34cbc2b217f3d907fa2ad6a0d7a813b0fda1e17fbeed94b0e0a0abfbec947146
        // Nonce =
        // PersonalizationString = e8fa4c5de825791e68180f2ba107e829c48299cb01be939cd0be76da120a91f2
        // EntropyInputReseed = 8326f8e9cfbd02eb076bbb9819d96a02386f80bf913c8e4a80361d82cafad52e
        // AdditionalInputReseed =
        // AdditionalInput =
        // AdditionalInput =
        // ReturnedBits =
        // 52f5e718bf48d99e498775c00378e545799bb2059aef0b74be573d8283f02b5293917913bc8f26fc23760a1c86c3f5c844857419868eafeb17c9248227d026b8

        byte[] entropy = HEX.parseHex("34cbc2b217f3d907fa2ad6a0d7a813b0fda1e17fbeed94b0e0a0abfbec947146");
        byte[] personalizationString = HEX.parseHex("e8fa4c5de825791e68180f2ba107e829c48299cb01be939cd0be76da120a91f2");
        byte[] entropyInputReseed = HEX.parseHex("8326f8e9cfbd02eb076bbb9819d96a02386f80bf913c8e4a80361d82cafad52e");
        byte[] additionalInputReseed = null;
        byte[] nonce = null;
        int bitLength = 128;
        ZwaveCryptoCtrDebugJsPort ctr = new ZwaveCryptoCtrDebugJsPort(bitLength, false, entropy, nonce,
                personalizationString);
        // ZwaveCryptoCtrDebugJsPort3 ctr = new ZwaveCryptoCtrDebugJsPort3(bitLength, false, entropy, nonce,
        // personalizationString);
        byte[] bytes = new byte[13];
        // random.nextBytes(bytes);
        ctr.reseed(entropyInputReseed, additionalInputReseed);
        bytes = ctr.generate(bytes.length, null);
        assertEquals(
                "52f5e718bf48d99e498775c00378e545799bb2059aef0b74be573d8283f02b5293917913bc8f26fc23760a1c86c3f5c844857419868eafeb17c9248227d026b8"
                        .toLowerCase(),
                HEX.formatHex(bytes));

    }
}
