package org.openhab.binding.zwave.internal.protocol.security.crypto.drbg;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * a port of ctr-drbg.js v14.x by DeepSeek
 */

public class ZwaveCryptoCtrDebugJsPortDave implements ZwaveCryptoCtrDebugV14Interface {

    private static final int KEY_LEN = 16;
    private static final int BLOCK_LEN = 16;
    private static final int SEED_LEN = KEY_LEN + BLOCK_LEN;

    private byte[] key = new byte[KEY_LEN];
    private byte[] v = new byte[BLOCK_LEN];

    public static class State {
        public byte[] key;
        public byte[] v;

        public State(byte[] key, byte[] v) {
            this.key = key.clone();
            this.v = v.clone();
        }
    }

    public State saveState() {
        return new State(key, v);
    }

    public void restoreState(State state) {
        this.key = state.key.clone();
        this.v = state.v.clone();
    }

    @Override
    public void init(byte[] entropy, byte[] personalizationString) {
        if (entropy.length != SEED_LEN) {
            throw new IllegalArgumentException("entropy must be " + SEED_LEN + " bytes long");
        }

        log("=== in init");
        log("entropy " + bytesToHex(entropy));
        log("ps " + bytesToHex(personalizationString));
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
        log("=update");
        log("provided=" + bytesToHex(providedData));
        byte[] temp = new byte[SEED_LEN];
        int tempOffset = 0;
        while (tempOffset < SEED_LEN) {
            log("increment pre  v=" + bytesToHex(this.v));
            increment(v);
            log("increment post v=" + bytesToHex(this.v));
            byte[] encrypted = encryptAES128ECB(v, key);
            System.arraycopy(encrypted, 0, temp, tempOffset, BLOCK_LEN);
            tempOffset += BLOCK_LEN;
        }

        if (providedData != null) {
            log("HAD provided");
            temp = xor(temp, providedData);
        }

        key = Arrays.copyOfRange(temp, 0, KEY_LEN);
        v = Arrays.copyOfRange(temp, KEY_LEN, SEED_LEN);
        log("key " + bytesToHex(key));
        log("v   " + bytesToHex(v));
    }

    @Override
    public byte[] generate(int len) {
        log("=generate");
        byte[] temp = new byte[(int) Math.ceil((double) len / BLOCK_LEN) * BLOCK_LEN];
        int tempOffset = 0;
        while (tempOffset < len) {
            increment(v);
            byte[] encrypted = encryptAES128ECB(v, key);
            System.arraycopy(encrypted, 0, temp, tempOffset, BLOCK_LEN);
            tempOffset += BLOCK_LEN;
        }

        update(null);

        byte[] result = Arrays.copyOfRange(temp, 0, len);
        log("gen " + bytesToHex(result));
        return result;
    }

    @Override
    public void reseed(byte[] entropy) {
        update(entropy);
    }

    private static void increment(byte[] array) {
        for (int i = array.length - 1; i >= 0; i--) {
            if (++array[i] != 0) {
                break;
            }
        }
    }

    private static byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
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

    public static String bytesToHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            // Convert each byte to a 2-digit hexadecimal string and append it to the hexString
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    public static void log(String message) {
        System.out.println(message);
    }
}