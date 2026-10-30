// Keccak-f[1600] core inspired by Markku-Juhani Saarinen's tiny_sha3 (sha3.c)
// https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c

public class SHA3SHAKE {

    private static final int KECCAKF_ROUNDS = 24;

    private long[] state;        // 1600-bit Keccak state (25 lanes × 64 bits)

    private int rateBytes;       // rate in bytes
    private int capacityBytes;   // capacity in bytes

    boolean isSHAKE;             // true = SHAKE, false = SHA-3
    private int suffix;          // store suffix for digest()

    private byte[] buffer;       // buffer for partial absorb blocks
    private int bufferPos;       // current position in buffer

    private boolean absorbing;   // true until squeeze/digest starts
    private boolean squeezing;   // true after squeeze/digest starts

    private int squeezeLane;
    private int squeezeLaneByte;

    private boolean finalized;
    private byte[] cachedDigest;

    public SHA3SHAKE() {
        state = new long[25];
    }

    /**
     * Initialize the SHA-3/SHAKE sponge.
     * The suffix must be one of 224, 256, 384, or 512 for SHA-3, or one of 128 or 256 for SHAKE.
     * @param suffix SHA-3/SHAKE suffix (SHA-3 digest bitlength = suffix, SHAKE sec level = suffix)
     */
    public void init(int suffix) {
        this.suffix = suffix;

        for (int i = 0; i < 25; i++) {
            state[i] = 0L;
        }

        absorbing = true;
        squeezing = false;
        squeezeLane = 0;
        squeezeLaneByte = 0;
        finalized = false;
        cachedDigest = null;

        if (!isSHAKE) {
            // SHA-3 mode
            switch (suffix) {
                case 224:
                    rateBytes = 1152 / 8;
                    capacityBytes = 448 / 8;
                    break;
                case 256:
                    rateBytes = 1088 / 8;
                    capacityBytes = 512 / 8;
                    break;
                case 384:
                    rateBytes = 832 / 8;
                    capacityBytes = 768 / 8;
                    break;
                case 512:
                    rateBytes = 576 / 8;
                    capacityBytes = 1024 / 8;
                    break;
                default:
                    throw new IllegalArgumentException("Invalid SHA-3 suffix: " + suffix);
            }
        } else {
            // SHAKE mode
            switch (suffix) {
                case 128:
                    rateBytes = 1344 / 8;
                    capacityBytes = 256 / 8;
                    break;
                case 256:
                    rateBytes = 1088 / 8;
                    capacityBytes = 512 / 8;
                    break;
                default:
                    throw new IllegalArgumentException("Invalid SHAKE suffix: " + suffix);
            }
        }

        buffer = new byte[rateBytes];
        bufferPos = 0;
    }

    /**
     * Update the SHA-3/SHAKE sponge with a byte-oriented data chunk.
     *
     * @param data byte-oriented data buffer
     * @param pos initial index to hash from
     * @param len byte count on the buffer
     */
    public void absorb(byte[] data, int pos, int len) {
        if (!absorbing) {
            throw new IllegalStateException("Cannot absorb after squeezing/digest without re-init.");
        }

        int i = 0;
        while (i < len) {
            int toCopy = Math.min(len - i, rateBytes - bufferPos);
            for (int k = 0; k < toCopy; k++) {
                buffer[bufferPos + k] ^= data[pos + i + k];
            }
            bufferPos += toCopy;
            i += toCopy;

            if (bufferPos == rateBytes) {
                absorbBlock();
                bufferPos = 0;
            }
        }
    }

    /**
     * Update the SHA-3/SHAKE sponge with a byte-oriented data chunk.
     *
     * @param data byte-oriented data buffer
     * @param len byte count on the buffer (starting at index 0)
     */
    public void absorb(byte[] data, int len) {
        absorb(data, 0, len);
    }

    /**
     * Update the SHA-3/SHAKE sponge with a byte-oriented data chunk.
     *
     * @param data byte-oriented data buffer
     */
    public void absorb(byte[] data) {
        absorb(data, 0, data.length);
    }

    private void absorbBlock() {
        int byteIndex = 0;
        for (int lane = 0; lane < 25 && byteIndex < rateBytes; lane++) {
            long v = state[lane];
            for (int b = 0; b < 8 && byteIndex < rateBytes; b++, byteIndex++) {
                v ^= ((long) (buffer[byteIndex] & 0xFF)) << (8 * b);
            }
            state[lane] = v;
        }
        keccakf(state);
        for (int i = 0; i < rateBytes; i++) {
            buffer[i] = 0;
        }
    }

    /**
     * Squeeze a chunk of hashed bytes from the sponge.
     * Call this method as many times as needed to extract the total desired number of bytes.
     *
     * @param out hash value buffer
     * @param len desired number of squeezed bytes
     * @return the val buffer containing the desired hash value
     */
    public byte[] squeeze(byte[] out, int len) {
        if (!isSHAKE) {
            throw new IllegalStateException("squeeze() is for SHAKE; use digest() for SHA-3.");
        }

        if (!squeezing) {
            absorbing = false;
            squeezing = true;
            shakePadAndPermute();
        }

        if (out == null || out.length < len) {
            out = new byte[len];
        }

        int produced = 0;

        while (produced < len) {
            if (squeezeLane == 25) {
                keccakf(state);
                squeezeLane = 0;
                squeezeLaneByte = 0;
            }
            long v = state[squeezeLane];

            out[produced++] = (byte) ((v >>> (8 * squeezeLaneByte)) & 0xFF);

            squeezeLaneByte++;

            if (squeezeLaneByte == 8) {
                squeezeLaneByte = 0;
                squeezeLane++;
            }
        }

        return out;
    }

    /**
     * Squeeze a chunk of hashed bytes from the sponge.
     * Call this method as many times as needed to extract the total desired number of bytes.
     *
     * @param len desired number of squeezed bytes
     * @return newly allocated buffer containing the desired hash value
     */
    public byte[] squeeze(int len) {
        return squeeze(null, len);
    }

    private void shakePadAndPermute() {
        buffer[bufferPos] ^= 0x1F;
        buffer[rateBytes - 1] ^= (byte) 0x80;
        absorbBlock();
        bufferPos = 0;
    }

    /**
     * Squeeze a whole SHA-3 digest of hashed bytes from the sponge.
     *
     * @param out hash value buffer
     * @return the val buffer containing the desired hash value
     */
    public byte[] digest(byte[] out) {

        if (finalized) {
            return cachedDigest.clone();
        }

        if (!absorbing) {
            throw new IllegalStateException(
                    "Cannot digest after squeeze(); re-init required."
            );
        }

        if (isSHAKE) {
            throw new IllegalStateException(
                    "digest() is for SHA-3; use squeeze() for SHAKE."
            );
        }

        absorbing = false;
        squeezing = true;

        buffer[bufferPos] ^= 0x06;
        buffer[rateBytes - 1] ^= (byte) 0x80;
        absorbBlock();

        int outLen = suffix / 8;

        if (out == null || out.length < outLen) {
            out = new byte[outLen];
        }

        int produced = 0;
        int lane = 0;
        int laneByte = 0;

        while (produced < outLen) {
            if (lane == 25) {
                keccakf(state);
                lane = 0;
                laneByte = 0;
            }

            long v = state[lane];

            out[produced++] =
                    (byte) ((v >>> (8 * laneByte)) & 0xFF);

            laneByte++;

            if (laneByte == 8) {
                laneByte = 0;
                lane++;
            }
        }

        cachedDigest = out.clone();
        finalized = true;

        return out;
    }

    /**
     * Squeeze a whole SHA-3 digest of hashed bytes from the sponge.
     *
     * @return the desired hash value on a newly allocated byte array
     */
    public byte[] digest() {
        return digest(null);
    }

    /**
     * Compute the streamlined SHA-3-<224,256,384,512> on input X.
     *
     * @param suffix desired output length in bits (one of 224, 256, 384, 512)
     * @param X data to be hashed
     * @param out hash value buffer (if null, this method allocates it with the required size)
     * @return the out buffer containing the desired hash value.
     */
    public static byte[] SHA3(int suffix, byte[] X, byte[] out) {
        SHA3SHAKE sha = new SHA3SHAKE();
        sha.isSHAKE = false;
        sha.init(suffix);
        sha.absorb(X);
        return sha.digest(out);
    }

    public static byte[] SHA3(int suffix, byte[] X) {
        return SHA3(suffix, X, null);
    }

    /**
     * Compute the streamlined SHAKE-<128,256> on input X with output bitlength L.
     *
     * @param suffix desired security level (either 128 or 256)
     * @param X data to be hashed
     * @param L desired output length in bits (must be a multiple of 8)
     * @param out hash value buffer (if null, this method allocates it with the required size)
     * @return the out buffer containing the desired hash value.
     */
    public static byte[] SHAKE(int suffix, byte[] X, int L, byte[] out) {
        if (L % 8 != 0) {
            throw new IllegalArgumentException("L must be a multiple of 8.");
        }
        int outBytes = L / 8;

        SHA3SHAKE shake = new SHA3SHAKE();
        shake.isSHAKE = true;
        shake.init(suffix);
        shake.absorb(X);
        return shake.squeeze(out, outBytes);
    }

    public static byte[] SHAKE(int suffix, byte[] X, int L) {
        return SHAKE(suffix, X, L, null);
    }

    // -------- Keccak-f[1600] core --------

    private static long rotl64(long x, int n) {
        return (x << n) | (x >>> (64 - n));
    }

    private static void keccakf(long[] st) {
        final long[] keccakf_rndc = {
                0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
                0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
                0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
                0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
                0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
                0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
                0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
                0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
        };

        final int[] keccakf_rotc = {
                1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
                27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
        };

        final int[] keccakf_piln = {
                10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
                15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
        };

        long[] bc = new long[5];

        for (int r = 0; r < KECCAKF_ROUNDS; r++) {

            // Theta
            for (int i = 0; i < 5; i++) {
                bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
            }
            for (int i = 0; i < 5; i++) {
                long t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
                for (int j = 0; j < 25; j += 5) {
                    st[j + i] ^= t;
                }
            }

            // Rho + Pi
            long t = st[1];
            for (int i = 0; i < 24; i++) {
                int j = keccakf_piln[i];
                long tmp = st[j];
                st[j] = rotl64(t, keccakf_rotc[i]);
                t = tmp;
            }

            // Chi
            for (int j = 0; j < 25; j += 5) {
                for (int i = 0; i < 5; i++) {
                    bc[i] = st[j + i];
                }
                for (int i = 0; i < 5; i++) {
                    st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
                }
            }

            // Iota
            st[0] ^= keccakf_rndc[r];
        }
    }
}
