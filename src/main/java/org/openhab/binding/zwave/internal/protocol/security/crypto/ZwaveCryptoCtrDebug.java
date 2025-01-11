package org.openhab.binding.zwave.internal.protocol.security.crypto;

import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * a port of ctr-drbg.js
 */
public class ZwaveCryptoCtrDebug {
    private static final int MAX_GENERATE_LENGTH = 65536;
    private final byte[] ctr;
    private final int keySize;
    private final int blkSize = 16;
    private final byte[] slab;
    private final byte[] K;
    private final byte[] V;
    private final boolean derivation;
    private boolean initialized;

    public ZwaveCryptoCtrDebug(int bits, boolean derivation, byte[] entropy, byte[] nonce, byte[] pers) {
        this.ctr = new byte[16];
        this.keySize = bits / 8;
        int entSize = this.keySize + this.blkSize;
        this.slab = new byte[entSize];
        this.K = Arrays.copyOfRange(slab, 0, keySize);
        this.V = Arrays.copyOfRange(slab, keySize, entSize);
        this.derivation = derivation;
        this.initialized = false;

        if (entropy != null) {
            init(entropy, nonce, pers);
        }
    }

    public void init(byte[] entropy, byte[] nonce, byte[] pers) {
        byte[] seed;
        if (derivation) {
            seed = derive(entropy, nonce, pers);
        } else {
            seed = new byte[keySize + blkSize];
            System.arraycopy(entropy, 0, seed, 0, entropy.length);
            System.arraycopy(nonce, 0, seed, entropy.length, nonce.length);
            for (int i = 0; i < pers.length; i++) {
                seed[i] ^= pers[i];
            }
        }
        Arrays.fill(slab, (byte) 0);
        System.arraycopy(V, 0, ctr, 0, V.length);
        update(seed);
        initialized = true;
    }

    public void reseed(byte[] entropy, byte[] additional) {
        if (!initialized) {
            throw new IllegalStateException("DRBG not initialized.");
        }

        byte[] seed;
        if (derivation) {
            seed = derive(entropy, additional);
        } else {
            seed = new byte[keySize + blkSize];
            System.arraycopy(entropy, 0, seed, 0, entropy.length);
            for (int i = 0; i < additional.length; i++) {
                seed[i] ^= additional[i];
            }
        }
        update(seed);
    }

    public byte[] generate(int len, byte[] additional) {
        if (!initialized) {
            throw new IllegalStateException("DRBG not initialized.");
        }
        if (len > MAX_GENERATE_LENGTH) {
            throw new IllegalArgumentException("Requested length too long.");
        }
        if (additional != null && additional.length > 0) {
            if (derivation) {
                additional = derive(additional);
            }
            update(additional);
        }

        byte[] out = new byte[(int) Math.ceil((double) len / blkSize) * blkSize];
        for (int i = 0; i < out.length; i += blkSize) {
            byte[] ciphertext = next();
            System.arraycopy(ciphertext, 0, out, i, blkSize);
        }
        update(additional);
        return Arrays.copyOfRange(out, 0, len);
    }

    private byte[] next() {
        incrementCounter();
        return encryptAES128ECB(ctr, K);
    }

    private void incrementCounter() {
        for (int i = ctr.length - 1; i >= 0; i--) {
            if (++ctr[i] != 0) {
                break;
            }
        }
    }

    private void update(byte[] seed) {
        byte[] newSlab = new byte[slab.length];
        for (int i = 0; i < newSlab.length; i += blkSize) {
            System.arraycopy(next(), 0, newSlab, i, blkSize);
        }
        for (int i = 0; i < seed.length; i++) {
            newSlab[i] ^= seed[i];
        }
        System.arraycopy(newSlab, 0, slab, 0, slab.length);
        System.arraycopy(V, 0, ctr, 0, V.length);
    }

    private byte[] derive(byte[]... inputs) {
        int size = blkSize + 4 + 4;
        for (byte[] input : inputs) {
            size += input.length;
        }
        byte[] S = new byte[size];
        int pos = blkSize;
        S[pos++] = (byte) ((size >>> 24) & 0xFF);
        S[pos++] = (byte) ((size >>> 16) & 0xFF);
        S[pos++] = (byte) ((size >>> 8) & 0xFF);
        S[pos++] = (byte) (size & 0xFF);

        for (byte[] input : inputs) {
            System.arraycopy(input, 0, S, pos, input.length);
            pos += input.length;
        }
        S[pos] = (byte) 0x80;
        return encryptAES128ECB(S, K);
    }

    private byte[] encryptAES128ECB(byte[] data, byte[] key) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}