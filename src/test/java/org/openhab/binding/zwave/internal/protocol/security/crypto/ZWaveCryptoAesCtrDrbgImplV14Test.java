package org.openhab.binding.zwave.internal.protocol.security.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.HexFormat;
import java.util.List;

import org.eclipse.jdt.annotation.NonNull;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.openhab.binding.zwave.internal.protocol.security.crypto.drbg.ZwaveCryptoCtrDebugJsPort2b;
import org.openhab.binding.zwave.internal.protocol.security.crypto.drbg.ZwaveCryptoCtrDebugJsPort3b;
import org.openhab.binding.zwave.internal.protocol.security.crypto.drbg.ZwaveCryptoCtrDebugJsPortDave;
import org.openhab.binding.zwave.internal.protocol.security.crypto.drbg.ZwaveCryptoCtrDebugV14Interface;

public class ZWaveCryptoAesCtrDrbgImplV14Test {
    private static final HexFormat HEX = HexFormat.of();

    static List<@NonNull ZwaveCryptoCtrDebugV14Interface> classes() {
        return List.of(new ZwaveCryptoCtrDebugJsPortDave(), new ZwaveCryptoCtrDebugJsPort2b(),
                new ZwaveCryptoCtrDebugJsPort3b());
    }

    @ParameterizedTest
    @MethodSource("classes")
    public void testCtrDrbgJsTestCaseDataLastOne(ZwaveCryptoCtrDebugV14Interface ctr) throws Exception {
        /**
         *
         *
         * [AES-128 no df]
         * [PredictionResistance = False]
         * [EntropyInputLen = 256]
         * [NonceLen = 0]
         * [PersonalizationStringLen = 0]
         * [AdditionalInputLen = 0]
         * [ReturnedBitsLen = 512]
         *
         * COUNT = 14
         * EntropyInput = e3d8fcb8c049e442d2bd07104c46f0602a1f60f87bdc02dbecdcfcf4006b5b0a
         * Nonce =
         * PersonalizationString =
         * EntropyInputReseed = e25327867ff27456eff9f4ae4375c7a85788b400dcae03ae8c892472c8a05221
         * AdditionalInputReseed =
         * AdditionalInput =
         * AdditionalInput =
         * ReturnedBits =
         * 754063c679269931fdab8f90deaa967969f20b1805d93fe5b1928512cd2fe98984974b0bb1d7494d81f53e073f1a3a9378ea27307a154dc8a1fb1d3e17998f85
         *
         *
         */
        int returnedBitsLen = 512;
        int returnedBytesLen = returnedBitsLen / 8;
        byte[] entropy = HEX.parseHex("e3d8fcb8c049e442d2bd07104c46f0602a1f60f87bdc02dbecdcfcf4006b5b0a");
        int entropyInputLenBits = 256;
        byte[] personalizationString = null;
        byte[] entropyInputReseed = HEX.parseHex("e25327867ff27456eff9f4ae4375c7a85788b400dcae03ae8c892472c8a05221");
        assertEquals(entropyInputLenBits / 8, entropy.length);

        // ZwaveCryptoCtrDebugV14Interface ctr = new ZwaveCryptoCtrDebugJsPort2b();
        ctr.init(entropy, personalizationString);
        ctr.reseed(entropyInputReseed);
        byte[] bytes = ctr.generate(returnedBytesLen);
        bytes = ctr.generate(returnedBytesLen);
        assertEquals(returnedBytesLen, bytes.length);
        assertEquals(
                "754063c679269931fdab8f90deaa967969f20b1805d93fe5b1928512cd2fe98984974b0bb1d7494d81f53e073f1a3a9378ea27307a154dc8a1fb1d3e17998f85"
                        .toLowerCase(),
                HEX.formatHex(bytes));

    }

    // @ParameterizedTest
    // @MethodSource("classes")
    public void testCtrDrbgJsTestCaseData(ZwaveCryptoCtrDebugV14Interface ctr) throws Exception {
        /**
         * [AES-128 no df]
         * [PredictionResistance = False]
         * [EntropyInputLen = 256]
         * [NonceLen = 0]
         * [PersonalizationStringLen = 0]
         * [AdditionalInputLen = 0]
         * [ReturnedBitsLen = 512]
         *
         * COUNT = 0
         * EntropyInput = ed1e7f21ef66ea5d8e2a85b9337245445b71d6393a4eecb0e63c193d0f72f9a9
         * Nonce =
         * PersonalizationString =
         * EntropyInputReseed = 303fb519f0a4e17d6df0b6426aa0ecb2a36079bd48be47ad2a8dbfe48da3efad
         * AdditionalInputReseed =
         * AdditionalInput =
         * AdditionalInput =
         * ReturnedBits =
         * f80111d08e874672f32f42997133a5210f7a9375e22cea70587f9cfafebe0f6a6aa2eb68e7dd9164536d53fa020fcab20f54caddfab7d6d91e5ffec1dfd8deaa
         */
        int returnedBitsLen = 512;
        int returnedBytesLen = returnedBitsLen / 8;
        byte[] entropy = HEX.parseHex("ed1e7f21ef66ea5d8e2a85b9337245445b71d6393a4eecb0e63c193d0f72f9a9");
        int entropyInputLenBits = 256;
        byte[] personalizationString = null;
        byte[] entropyInputReseed = HEX.parseHex("303fb519f0a4e17d6df0b6426aa0ecb2a36079bd48be47ad2a8dbfe48da3efad");
        assertEquals(entropyInputLenBits / 8, entropy.length);

        // ZwaveCryptoCtrDebugV14Interface ctr = new ZwaveCryptoCtrDebugJsPort2b();
        ctr.init(entropy, personalizationString);
        ctr.reseed(entropyInputReseed);
        byte[] bytes = ctr.generate(returnedBytesLen);
        assertEquals(returnedBytesLen, bytes.length);
        assertEquals(
                "f80111d08e874672f32f42997133a5210f7a9375e22cea70587f9cfafebe0f6a6aa2eb68e7dd9164536d53fa020fcab20f54caddfab7d6d91e5ffec1dfd8deaa"
                        .toLowerCase(),
                HEX.formatHex(bytes));

    }

    // @ParameterizedTest
    // @ValueSource(classes = {ZwaveCryptoCtrDebugJsPort2b.class, ZwaveCryptoCtrDebugJsPort3b.class})
    // public void testCtrDrbg(ZwaveCryptoCtrDebugV14Interface ctr) throws Exception {
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
        ZwaveCryptoCtrDebugV14Interface ctr = new ZwaveCryptoCtrDebugJsPort2b();
        ctr.init(entropy, personalizationString);
        // ZwaveCryptoCtrDebugJsPort ctr = new ZwaveCryptoCtrDebugJsPort(128, false, entropy, nonce,
        // personalizationString);
        byte[] bytes = new byte[13];
        // random.nextBytes(bytes);
        bytes = ctr.generate(bytes.length);

        assertEquals("23af81e2db91cd015abac40954".toLowerCase(), HEX.formatHex(bytes));
        // random.nextBytes(bytes);
        bytes = ctr.generate(bytes.length);
        assertEquals("4b2b196800b2913ef749d58972".toLowerCase(), HEX.formatHex(bytes));
    }

}
