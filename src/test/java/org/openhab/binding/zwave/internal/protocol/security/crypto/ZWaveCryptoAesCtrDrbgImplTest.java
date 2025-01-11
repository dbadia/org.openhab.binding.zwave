package org.openhab.binding.zwave.internal.protocol.security.crypto;

import java.util.HexFormat;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class ZWaveCryptoAesCtrDrbgImplTest {
    private static final HexFormat HEX = HexFormat.of();

    @Disabled
    @Test
    public void testCtrDrbg() throws Exception {
        /*
         * 128,
         * derivation = false,
         * entropy = MEI,
         * nonce = undefined,
         * personalizationString = keys.personalizationString,
         */
        ZWaveCryptoAesCtrDrbgOurImpl ctrDrbg = new ZWaveCryptoAesCtrDrbgOurImpl();
        byte[] entropy = HEX.parseHex("bacfa8c486ac1b6f74d0f560e647e68972b7d18d256ad7fa5552fa8a5769519d");
        byte[] personalizationString = HEX.parseHex("8bece5005a4cdcfa855d597b2590eeb38b35b2e7a90d55ca8c8a2507d4a182ff");
        // SecureRandom random = ctrDrbg.buildAesCounterModeDeterministicRandomNumberGenerator(entropy,
        // personalizationString, false);
        // int bits, boolean derivation, byte[] entropy, byte[] nonce, byte[] pers
        // ZwaveCryptoCtrDebug ctr = new ZwaveCryptoCtrDebug(128, false, entropy, entropy, personalizationString)
        // byte[] bytes = new byte[16];
        // random.nextBytes(bytes);
        // assertEquals("23af81e2db91cd015abac40954".toLowerCase(), HEX.formatHex(bytes));
        // random.nextBytes(bytes);
        // assertEquals("4b2b196800b2913ef749d58972".toLowerCase(), HEX.formatHex(bytes));
    }
}
