package org.openhab.binding.zwave.internal.protocol.security.crypto;

import static org.openhab.binding.zwave.internal.protocol.commandclass.ZWaveSecurity0CommandClass.hexToBytes;

import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

import org.openhab.binding.zwave.internal.protocol.security.ZWaveSecurityNetworkKeys;
import org.openhab.binding.zwave.internal.protocol.security.crypto.interfaces.ZWaveCryptoAesAeadCcm;
import org.openhab.binding.zwave.internal.protocol.security.crypto.interfaces.ZWaveCryptoAesCtrDrbg;
import org.openhab.binding.zwave.internal.protocol.security.crypto.interfaces.ZWaveCryptoDiffieHellman;
import org.openhab.binding.zwave.internal.protocol.security.enums.ZWaveKeyType;

public class CryptoInitTestHelper {
    public static volatile ZWaveSecurityNetworkKeys keys;
    private static ZWaveCryptoOperations cryptoOperations;

    public static synchronized void initCryptoForTesting(ZWaveCryptoAesAeadCcm aeadCcmProvider,
            final ZWaveCryptoAesCtrDrbg ctrDrbgProvider) {
        if (keys == null) {
            ZWaveSecurityNetworkKeys tempKeys = new ZWaveSecurityNetworkKeys();
            tempKeys.addKey(ZWaveKeyType.S0, new SecretKeySpec(hexToBytes("00000000000000000000000000000000"), "AES"));
            tempKeys.addKey(ZWaveKeyType.S2_UNAUTHENTICATED,
                    new SecretKeySpec(hexToBytes("11111111111111111111111111111111"), "AES"));
            tempKeys.addKey(ZWaveKeyType.S2_AUTHENTICATED,
                    new SecretKeySpec(hexToBytes("22222222222222222222222222222222"), "AES"));
            tempKeys.addKey(ZWaveKeyType.S2_ACCESS_CONTROL,
                    new SecretKeySpec(hexToBytes("33333333333333333333333333333333"), "AES"));
            final ZWaveCryptoDiffieHellman diffieHellmanProvider = new ZWaveCryptoDiffieHellmanJdk();
            SecureRandom prng = new SecureRandom(); // for testing, just use this since it's fast
            cryptoOperations = new ZWaveCryptoOperations(tempKeys, aeadCcmProvider, ctrDrbgProvider,
                    diffieHellmanProvider, prng);
            ZWaveCryptoOperationsFactory.instance = cryptoOperations;
            keys = tempKeys;
        }
    }
}
