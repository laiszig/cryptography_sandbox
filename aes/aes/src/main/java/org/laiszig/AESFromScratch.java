package org.laiszig;


public class AESFromScratch {


    static void main(String[] args) {
        String message = "AES from scratch is fun!";

        byte[] key = generateKey();

        byte[] encrypted = encryptText(message, key);
        System.out.println("Encrypted (hex): " + toHex(encrypted));

        String decrypted = decryptText(encrypted, key);
        System.out.println("Decrypted: " + decrypted);
    }

    static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    static byte[] encrypt(byte[] plaintext, byte[] key) {
        byte[][] state = new byte[4][4];

        // load state
        for (int i = 0; i < 16; i++)
            state[i % 4][i / 4] = plaintext[i];

        byte[][][] roundKeys = expandKey(key);

        addRoundKey(state, roundKeys[0]);

        for (int round = 1; round < 10; round++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, roundKeys[round]);
        }

        // last round (no MixColumns)
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, roundKeys[10]);

        byte[] output = new byte[16];
        for (int i = 0; i < 16; i++)
            output[i] = state[i % 4][i / 4];

        return output;
    }

    static void addRoundKey(byte[][] state, byte[][] key) {
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                state[i][j] ^= key[i][j];
    }

    static void mixColumns(byte[][] s) {
        for (int c = 0; c < 4; c++) {
            byte a0 = s[0][c], a1 = s[1][c], a2 = s[2][c], a3 = s[3][c];

            s[0][c] = (byte)(gmul(a0 & 0xFF,2) ^ gmul(a1 & 0xFF,3) ^ a2 ^ a3);
            s[1][c] = (byte)(a0 ^ gmul(a1 & 0xFF,2) ^ gmul(a2 & 0xFF,3) ^ a3);
            s[2][c] = (byte)(a0 ^ a1 ^ gmul(a2 & 0xFF,2) ^ gmul(a3 & 0xFF,3));
            s[3][c] = (byte)(gmul(a0 & 0xFF,3) ^ a1 ^ a2 ^ gmul(a3 & 0xFF,2));
        }
    }

    static void shiftRows(byte[][] s) {
        for (int i = 1; i < 4; i++) {
            byte[] row = s[i].clone();
            for (int j = 0; j < 4; j++) {
                s[i][j] = row[(j + i) % 4];
            }
        }
    }

    static void subBytes(byte[][] state) {
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                state[i][j] = (byte) sBox(state[i][j] & 0xFF);
    }

    static final int[] RCON = {
            0x01,0x02,0x04,0x08,0x10,
            0x20,0x40,0x80,0x1B,0x36
    };

    static byte[][][] expandKey(byte[] key) {
        byte[][][] roundKeys = new byte[11][4][4];

        // first key
        for (int i = 0; i < 16; i++) {
            roundKeys[0][i % 4][i / 4] = key[i];
        }

        for (int r = 1; r <= 10; r++) {
            byte[][] prev = roundKeys[r - 1];
            byte[][] curr = new byte[4][4];

            // last column
            byte[] temp = new byte[4];
            for (int i = 0; i < 4; i++)
                temp[i] = prev[i][3];

            // RotWord
            byte t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            // SubBytes
            for (int i = 0; i < 4; i++)
                temp[i] = (byte) sBox(temp[i] & 0xFF);

            // RCON
            temp[0] ^= RCON[r - 1];

            // first column
            for (int i = 0; i < 4; i++)
                curr[i][0] = (byte) (prev[i][0] ^ temp[i]);

            // remaining columns
            for (int col = 1; col < 4; col++) {
                for (int i = 0; i < 4; i++) {
                    curr[i][col] = (byte) (prev[i][col] ^ curr[i][col - 1]);
                }
            }

            roundKeys[r] = curr;
        }

        return roundKeys;
    }


    static int multiplicativeInverse(int x) {
        if (x == 0) return 0;

        for (int i = 1; i < 256; i++) {
            if (gmul(x, i) == 1)
                return i;
        }
        return 0;
    }

    static int sBox(int x) {
        int inv = multiplicativeInverse(x);

        int result = inv;
        for (int i = 0; i < 4; i++) {
            inv = (inv << 1) | (inv >> 7);
            result ^= inv;
        }
        result ^= 0x63;

        return result & 0xFF;
    }

    // S-Box function
    static int gmul(int a, int b) {
        int p = 0;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) != 0)
                p ^= a;
            boolean hiBitSet = (a & 0x80) != 0;
            a <<= 1;
            if (hiBitSet)
                a ^= 0x1b;
            b >>= 1;
        }
        return p & 0xFF;
    }

    static byte[] stringToBytes(String input) {
        return input.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    static String bytesToString(byte[] bytes) {
        return new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
    }

    static byte[] pad(byte[] input) {
        int padding = 16 - (input.length % 16);
        byte[] output = new byte[input.length + padding];

        System.arraycopy(input, 0, output, 0, input.length);

        for (int i = input.length; i < output.length; i++) {
            output[i] = (byte) padding;
        }

        return output;
    }

    static byte[] unpad(byte[] input) {
        int padding = input[input.length - 1] & 0xFF;
        byte[] output = new byte[input.length - padding];

        System.arraycopy(input, 0, output, 0, output.length);
        return output;
    }

    static byte[][] splitBlocks(byte[] data) {
        int blocks = data.length / 16;
        byte[][] result = new byte[blocks][16];

        for (int i = 0; i < blocks; i++) {
            System.arraycopy(data, i * 16, result[i], 0, 16);
        }

        return result;
    }

    static byte[] joinBlocks(byte[][] blocks) {
        byte[] result = new byte[blocks.length * 16];

        for (int i = 0; i < blocks.length; i++) {
            System.arraycopy(blocks[i], 0, result, i * 16, 16);
        }

        return result;
    }

    static byte[] generateKey() {
        java.security.SecureRandom random = new java.security.SecureRandom();
        byte[] key = new byte[16];
        random.nextBytes(key);
        return key;
    }

    static int invSBox(int x) {
        for (int i = 0; i < 256; i++) {
            if (sBox(i) == x) return i;
        }
        return 0;
    }

    static void invSubBytes(byte[][] state) {
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                state[i][j] = (byte) invSBox(state[i][j] & 0xFF);
    }

    static void invShiftRows(byte[][] s) {
        for (int i = 1; i < 4; i++) {
            byte[] row = s[i].clone();
            for (int j = 0; j < 4; j++) {
                s[i][(j + i) % 4] = row[j];
            }
        }
    }

    static void invMixColumns(byte[][] s) {
        for (int c = 0; c < 4; c++) {
            byte a0 = s[0][c], a1 = s[1][c], a2 = s[2][c], a3 = s[3][c];

            s[0][c] = (byte)(gmul(a0 & 0xFF,14) ^ gmul(a1 & 0xFF,11) ^ gmul(a2 & 0xFF,13) ^ gmul(a3 & 0xFF,9));
            s[1][c] = (byte)(gmul(a0 & 0xFF,9)  ^ gmul(a1 & 0xFF,14) ^ gmul(a2 & 0xFF,11) ^ gmul(a3 & 0xFF,13));
            s[2][c] = (byte)(gmul(a0 & 0xFF,13) ^ gmul(a1 & 0xFF,9)  ^ gmul(a2 & 0xFF,14) ^ gmul(a3 & 0xFF,11));
            s[3][c] = (byte)(gmul(a0 & 0xFF,11) ^ gmul(a1 & 0xFF,13) ^ gmul(a2 & 0xFF,9)  ^ gmul(a3 & 0xFF,14));
        }
    }

    static byte[] decrypt(byte[] ciphertext, byte[] key) {
        byte[][] state = new byte[4][4];

        // load state
        for (int i = 0; i < 16; i++)
            state[i % 4][i / 4] = ciphertext[i];

        byte[][][] roundKeys = expandKey(key);

        // start with last key
        addRoundKey(state, roundKeys[10]);

        for (int round = 9; round > 0; round--) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, roundKeys[round]);
            invMixColumns(state);
        }

        // final round (no InvMixColumns)
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, roundKeys[0]);

        byte[] output = new byte[16];
        for (int i = 0; i < 16; i++)
            output[i] = state[i % 4][i / 4];

        return output;
    }

    static byte[] encryptText(String text, byte[] key) {
        byte[] data = stringToBytes(text);
        byte[] padded = pad(data);

        byte[][] blocks = splitBlocks(padded);
        byte[][] encryptedBlocks = new byte[blocks.length][16];

        for (int i = 0; i < blocks.length; i++) {
            encryptedBlocks[i] = encrypt(blocks[i], key);
        }

        return joinBlocks(encryptedBlocks);
    }

    static String decryptText(byte[] ciphertext, byte[] key) {
        byte[][] blocks = splitBlocks(ciphertext);
        byte[][] decryptedBlocks = new byte[blocks.length][16];

        for (int i = 0; i < blocks.length; i++) {
            decryptedBlocks[i] = decrypt(blocks[i], key);
        }

        byte[] joined = joinBlocks(decryptedBlocks);
        byte[] unpadded = unpad(joined);

        return bytesToString(unpadded);
    }
}
