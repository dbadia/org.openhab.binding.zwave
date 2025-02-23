package org.openhab.binding.zwave.internal.protocol.security.crypto.drbg.old;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * a port of ctr-drbg.js by Deepseek
 */
public class ZwaveCryptoCtrDebugJsPort3 {
    private static final int MAX_GENERATE_LENGTH = 65536;
    private static final int AES_BLOCK_SIZE = 16;

    private byte[] ctr;
    private final int keySize;
    private final int blkSize;
    private final int entSize;
    private byte[] slab;
    private byte[] K;
    private byte[] V;
    private final boolean derivation;
    private boolean initialized;

    public ZwaveCryptoCtrDebugJsPort3(int bits, boolean derivation, byte[] entropy, byte[] nonce, byte[] pers) {
        this.ctr = new byte[16];
        this.keySize = bits / 8;
        this.blkSize = 16;
        this.entSize = this.keySize + this.blkSize;
        this.slab = new byte[this.entSize];
        this.K = Arrays.copyOfRange(this.slab, 0, this.keySize);
        this.V = Arrays.copyOfRange(this.slab, this.keySize, this.entSize);
        this.derivation = derivation;
        this.initialized = false;

        if (entropy != null) {
            this.init(entropy, nonce, pers);
        }
    }

    public ZwaveCryptoCtrDebugJsPort3 init(byte[] entropy, byte[] nonce, byte[] pers) {
        byte[] seed;

        if (this.derivation) {
            seed = this.derive(entropy, nonce, pers);
        } else {
            if (entropy.length + (nonce != null ? nonce.length : 0) > this.entSize) {
                throw new IllegalArgumentException("Entropy is too long.");
            }

            if (pers != null && pers.length > this.entSize) {
                throw new IllegalArgumentException("Personalization string is too long.");
            }

            seed = new byte[this.entSize];
            System.arraycopy(entropy, 0, seed, 0, entropy.length);
            if (nonce != null) {
                System.arraycopy(nonce, 0, seed, entropy.length, nonce.length);
            }

            if (pers != null) {
                for (int i = 0; i < pers.length; i++) {
                    seed[i] ^= pers[i];
                }
            }
        }

        Arrays.fill(this.slab, (byte) 0);
        System.arraycopy(this.V, 0, this.ctr, 0, this.V.length);
        this.update(seed);
        this.initialized = true;

        return this;
    }

    public ZwaveCryptoCtrDebugJsPort3 reseed(byte[] entropy, byte[] add) {
        if (!this.initialized) {
            throw new IllegalStateException("DRBG not initialized.");
        }

        byte[] seed;

        if (this.derivation) {
            seed = this.derive(entropy, add);
        } else {
            if (add != null && add.length > this.entSize) {
                throw new IllegalArgumentException("Additional data is too long.");
            }

            seed = new byte[this.entSize];
            System.arraycopy(entropy, 0, seed, 0, entropy.length);
            if (add != null) {
                for (int i = 0; i < add.length; i++) {
                    seed[i] ^= add[i];
                }
            }
        }

        this.update(seed);

        return this;
    }

    private byte[] next() {
        increment(this.ctr);
        return encryptAES128ECB(this.ctr, this.K);
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
                add = this.derive(add);
            }

            this.update(add);
        }

        int blocks = (int) Math.ceil((double) len / this.blkSize);
        byte[] out = new byte[blocks * this.blkSize];

        for (int i = 0; i < blocks; i++) {
            byte[] ciphertext = this.next();
            System.arraycopy(ciphertext, 0, out, i * this.blkSize, ciphertext.length);
        }

        this.update(add);
        this.initialized = true;

        return Arrays.copyOfRange(out, 0, len);
    }

    private ZwaveCryptoCtrDebugJsPort3 update(byte[] seed) {
        if (seed != null && seed.length > this.entSize) {
            throw new IllegalArgumentException("Seed is too long.");
        }

        byte[] newSlab = new byte[this.slab.length];
        Arrays.fill(newSlab, (byte) 0);

        for (int i = 0; i < this.entSize; i += this.blkSize) {
            byte[] ciphertext = this.next();
            System.arraycopy(ciphertext, 0, newSlab, i, ciphertext.length);
        }

        if (seed != null) {
            for (int i = 0; i < seed.length; i++) {
                newSlab[i] ^= seed[i];
            }
        }

        System.arraycopy(newSlab, 0, this.slab, 0, newSlab.length);
        System.arraycopy(this.V, 0, this.ctr, 0, this.V.length);

        return this;
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
        S.position(this.blkSize);
        S.putInt(L);
        S.putInt(N);

        for (byte[] item : input) {
            S.put(item);
        }

        S.put((byte) 0x80);

        return S.array();
    }

    private byte[] derive(byte[]... input) {
        byte[] S = this.serialize(input);
        int N = S.length / this.blkSize;
        byte[] K = new byte[this.keySize];
        int blocks = (int) Math.ceil((double) this.entSize / this.blkSize);
        byte[] slab = new byte[blocks * this.blkSize];
        byte[] out = new byte[blocks * this.blkSize];
        byte[] chain = new byte[this.blkSize];

        for (int i = 0; i < K.length; i++) {
            K[i] = (byte) i;
        }

        for (int i = 0; i < blocks; i++) {
            Arrays.fill(chain, (byte) 0);

            ByteBuffer.wrap(S).putInt(0, i);

            for (int j = 0; j < N; j++) {
                for (int k = 0; k < chain.length; k++) {
                    chain[k] ^= S[j * this.blkSize + k];
                }

                chain = encryptAES128ECB(chain, K);
            }

            System.arraycopy(chain, 0, slab, i * this.blkSize, chain.length);
        }

        byte[] k = Arrays.copyOfRange(slab, 0, this.keySize);
        byte[] x = Arrays.copyOfRange(slab, this.keySize, this.entSize);

        for (int i = 0; i < blocks; i++) {
            x = encryptAES128ECB(x, k);
            System.arraycopy(x, 0, out, i * this.blkSize, x.length);
        }

        return Arrays.copyOfRange(out, 0, this.entSize);
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