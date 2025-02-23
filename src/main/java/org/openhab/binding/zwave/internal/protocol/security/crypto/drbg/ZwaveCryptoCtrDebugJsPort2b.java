package org.openhab.binding.zwave.internal.protocol.security.crypto.drbg;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * a port of ctr-drbg.js v14.x by MS copilot
 */
public class ZwaveCryptoCtrDebugJsPort2b implements ZwaveCryptoCtrDebugV14Interface {
    private static final int KEY_LEN = 16;
    private static final int BLOCK_LEN = 16;
    private static final int SEED_LEN = KEY_LEN + BLOCK_LEN;

    private byte[] key = new byte[KEY_LEN];
    private byte[] v = new byte[BLOCK_LEN];

    // Reseed counter is not used

    public byte[] getKey() {
        return Arrays.copyOf(key, key.length);
    }

    public byte[] getV() {
        return Arrays.copyOf(v, v.length);
    }

    public void saveState(byte[] key, byte[] v) {
        this.key = Arrays.copyOf(key, key.length);
        this.v = Arrays.copyOf(v, v.length);
    }

    @Override
    public void init(byte[] entropy, byte[] personalizationString) {
        if (entropy.length != SEED_LEN) {
            throw new IllegalArgumentException("entropy must be " + SEED_LEN + " bytes long");
        }

        if (personalizationString != null) {
            if (personalizationString.length > SEED_LEN) {
                throw new IllegalArgumentException("Personalization string is too long.");
            }
            for (int i = 0; i < personalizationString.length; i++) {
                entropy[i] ^= personalizationString[i];
            }
        }

        update(entropy);
    }

    public void update(byte[] providedData) {
        if (providedData != null && providedData.length != SEED_LEN) {
            throw new IllegalArgumentException("providedData must be " + SEED_LEN + " bytes long");
        }

        byte[] temp = new byte[SEED_LEN];
        int tempOffset = 0;
        while (tempOffset < SEED_LEN) {
            increment(this.v);
            byte[] encrypted = encryptAES128ECB(this.v, this.key);
            System.arraycopy(encrypted, 0, temp, tempOffset, BLOCK_LEN);
            tempOffset += BLOCK_LEN;
        }

        if (providedData != null) {
            for (int i = 0; i < SEED_LEN; i++) {
                temp[i] ^= providedData[i];
            }
        }

        this.key = Arrays.copyOfRange(temp, 0, KEY_LEN);
        this.v = Arrays.copyOfRange(temp, KEY_LEN, temp.length);
    }

    @Override
    public byte[] generate(int len) {
        byte[] temp = new byte[(int) Math.ceil((double) len / BLOCK_LEN) * BLOCK_LEN];
        int tempOffset = 0;
        while (tempOffset < len) {
            increment(this.v);
            byte[] encrypted = encryptAES128ECB(this.v, this.key);
            System.arraycopy(encrypted, 0, temp, tempOffset, BLOCK_LEN);
            tempOffset += BLOCK_LEN;
        }

        update(null);

        return Arrays.copyOfRange(temp, 0, len);
    }

    @Override
    public void reseed(byte[] entropy) {
        update(entropy);
    }

    private static void increment(byte[] counter) {
        for (int i = counter.length - 1; i >= 0; i--) {
            if (++counter[i] != 0) {
                break;
            }
        }
    }

    private static byte[] encryptAES128ECB(byte[] input, byte[] key) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(input);
        } catch (NoSuchAlgorithmException | InvalidKeyException | javax.crypto.NoSuchPaddingException
                | javax.crypto.IllegalBlockSizeException | javax.crypto.BadPaddingException e) {
            throw new RuntimeException("AES encryption failed", e);
        }
    }
}
