package org.openhab.binding.zwave.internal.protocol.security.crypto.drbg.old;

import java.nio.ByteBuffer;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * a port of ctr-drbg.js by MS copilot
 */
public class ZwaveCryptoCtrDebugJsPort2 {
    private static final int MAX_GENERATE_LENGTH = 65536;

    private ByteBuffer ctr;
    private final int keySize;
    private final int blkSize;
    private final int entSize;
    private byte[] slab;
    private byte[] K;
    private byte[] V;
    private final boolean derivation;
    private boolean initialized;

    public ZwaveCryptoCtrDebugJsPort2(int bits, boolean derivation, byte[] entropy, byte[] nonce, byte[] pers) {
        this.ctr = ByteBuffer.allocate(16);
        this.keySize = bits >>> 3;
        this.blkSize = 16;
        this.entSize = this.keySize + this.blkSize;
        this.slab = new byte[this.entSize];
        this.K = Arrays.copyOfRange(this.slab, 0, this.keySize);
        this.V = Arrays.copyOfRange(this.slab, this.keySize, this.slab.length);
        this.derivation = derivation;
        this.initialized = false;

        if (entropy != null) {
            init(entropy, nonce, pers);
        }
    }

    public ZwaveCryptoCtrDebugJsPort2 init(byte[] entropy, byte[] nonce, byte[] pers) {
        if (nonce == null) {
            nonce = new byte[0];
        }
        if (pers == null) {
            pers = new byte[0];
        }

        byte[] seed;

        if (this.derivation) {
            seed = derive(entropy, nonce, pers);
        } else {
            if (entropy.length + nonce.length > this.entSize) {
                throw new IllegalArgumentException("Entropy is too long.");
            }

            if (pers.length > this.entSize) {
                throw new IllegalArgumentException("Personalization string is too long.");
            }

            seed = new byte[this.entSize];
            System.arraycopy(entropy, 0, seed, 0, entropy.length);
            System.arraycopy(nonce, 0, seed, entropy.length, nonce.length);

            for (int i = 0; i < pers.length; i++) {
                seed[i] ^= pers[i];
            }
        }

        Arrays.fill(this.slab, (byte) 0);
        System.arraycopy(this.V, 0, this.ctr.array(), 0, this.V.length);
        update(seed);
        this.initialized = true;

        return this;
    }

    public ZwaveCryptoCtrDebugJsPort2 reseed(byte[] entropy, byte[] add) {
        if (!this.initialized) {
            throw new IllegalStateException("DRBG not initialized.");
        }

        if (add == null) {
            add = new byte[0];
        }

        byte[] seed;

        if (this.derivation) {
            seed = derive(entropy, add);
        } else {
            if (add.length > this.entSize) {
                throw new IllegalArgumentException("Additional data is too long.");
            }

            seed = new byte[this.entSize];
            System.arraycopy(entropy, 0, seed, 0, entropy.length);
            for (int i = 0; i < add.length; i++) {
                seed[i] ^= add[i];
            }
        }

        update(seed);
        return this;
    }

    private byte[] next() {
        increment(this.ctr.array());
        return encryptAES128ECB(this.ctr.array(), this.K);
    }

    public byte[] generate(int len, byte[] add) {
        if (!this.initialized) {
            throw new IllegalStateException("DRBG not initialized.");
        }

        if (len > MAX_GENERATE_LENGTH) {
            throw new IllegalArgumentException("Requested length is too long.");
        }

        if (add != null && add.length > 0) {
            if (this.derivation) {
                add = derive(add);
            }
            update(add);
        }

        int blocks = (int) Math.ceil((double) len / this.blkSize);
        byte[] out = new byte[blocks * this.blkSize];

        for (int i = 0; i < blocks; i++) {
            byte[] ciphertext = next();
            System.arraycopy(ciphertext, 0, out, i * this.blkSize, ciphertext.length);
        }

        update(add);
        this.initialized = true;

        return Arrays.copyOfRange(out, 0, len);
    }

    private void update(byte[] seed) {
        if (seed.length > this.entSize) {
            throw new IllegalArgumentException("Seed is too long.");
        }

        byte[] newSlab = new byte[this.slab.length];

        for (int i = 0; i < this.entSize; i += this.blkSize) {
            byte[] nextVal = next();
            System.arraycopy(nextVal, 0, newSlab, i, nextVal.length);
        }

        for (int i = 0; i < seed.length; i++) {
            newSlab[i] ^= seed[i];
        }

        System.arraycopy(newSlab, 0, this.slab, 0, newSlab.length);
        System.arraycopy(this.V, 0, this.ctr.array(), 0, this.V.length);
    }

    private byte[] serialize(byte[]... input) {
        int N = this.entSize;
        int L = 0;

        for (byte[] item : input) {
            L += item.length;
        }

        int size = this.blkSize + 4 + 4 + L + 1;
        if (size % this.blkSize != 0) {
            size += this.blkSize - (size % this.blkSize);
        }

        ByteBuffer S = ByteBuffer.allocate(size);
        S.put(new byte[this.blkSize]);
        S.putInt(L);
        S.putInt(N);

        for (byte[] item : input) {
            S.put(item);
        }

        S.put((byte) 0x80);

        return S.array();
    }

    private byte[] derive(byte[]... input) {
        byte[] S = serialize(input);
        int N = S.length / this.blkSize;
        byte[] K = new byte[this.keySize];
        Arrays.fill(K, (byte) 0);

        int blocks = (int) Math.ceil((double) this.entSize / this.blkSize);
        byte[] slab = new byte[blocks * this.blkSize];
        byte[] out = new byte[blocks * this.blkSize];
        byte[] chain = new byte[this.blkSize];

        for (int i = 0; i < K.length; i++) {
            K[i] = (byte) i;
        }

        for (int i = 0; i < blocks; i++) {
            Arrays.fill(chain, (byte) 0);
            S[0] = (byte) i;

            for (int j = 0; j < N; j++) {
                for (int k = 0; k < chain.length; k++) {
                    chain[k] ^= S[j * this.blkSize + k];
                }

                byte[] encryptedChain = encryptAES128ECB(chain, K);
                System.arraycopy(encryptedChain, 0, chain, 0, encryptedChain.length);
            }

            System.arraycopy(chain, 0, slab, i * this.blkSize, chain.length);
        }

        byte[] k = Arrays.copyOfRange(slab, 0, this.keySize);
        byte[] x = Arrays.copyOfRange(slab, this.keySize, this.entSize);

        for (int i = 0; i < blocks; i++) {
            byte[] encryptedX = encryptAES128ECB(x, k);
            System.arraycopy(encryptedX, 0, x, 0, encryptedX.length);
            System.arraycopy(x, 0, out, i * this.blkSize, x.length);
        }

        return Arrays.copyOfRange(out, 0, this.entSize);
    }

    // Placeholder methods for increment and encryptAES128ECB
    private void increment(byte[] array) {
        // Implement the increment logic here
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
