package org.laiszig;

import java.nio.charset.StandardCharsets;

/*
    1. Initial Permutation (IP)
    - Rearrange the order of bits using a predefined table (IP)
    2. Key Transformation
    - Initial 64-bit key is converted into 56-bit key (Goes through Permutated Choice 1 (PC-1)
        - In PC-1 every eighth bit in key is discarded (8, 16, 24, 32, 40, 48, 56, and 64) - parity bits (error checking)
        - Remaining 56-bits are split into two 28-bit halves (Left half - Ci and Right half - Di)
    - Ci and Di undergo circular left shift operation
        - For Feistel round 1, 2, 9, and 16 both halves (left and right) undergo 1-bit left shift operation
        - For others rounds (3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15) the halves undergo 2-bit left shift operation
    - This then generates 48-bit subkeys for each of the 16 Feistel rounds
    - Ci and Di are combined into 56-bit block to go through PC-2
        - PC-2 selects 48 bits from the combined Ci and Di to create the subkey for the round
        - The output subkey is used to cipher the plain text in the Feistel round
     3. Feistel Rounds
     - Every round receives 64-bits permuted plaintext from the IP function and 48-bit transformed subkey (Ki)
     - The permuted 64-bit plaintext is divided into two halves called as Left Plaintext (LPT) and Right Plaintext (RPT)
     - RPT is processed using Mangler (F) function
        - RPT is expanded from 32-bits to 48-bits using Expansion (E) function
        - The expanded RPT is XORed with the subkey (Ki) for the round
        - The output of XOR operation is then passed through 8 S-boxes (Substitution boxes)
            - Each S-box takes 6 bits as input and produces 4 bits as output
                - 1st and last bit are joined and converted to decimal (to find row number in S-box)
                - Middle 4 bits are converted to decimal (to find column number in S-box)
                - The value at the intersection of row and column in the S-box is the output
                - Ex: 101010 -> (1)(0101)(0) -> divided into 10 and 0101 -> row 2 and column 5 -> value at S-box[2][5] is the output
                    6-bit chunk: '101010' converted into 4-bit chunk: '0110' (In s1, row 2 and column 5 gives value 6)
            - The 32-bit output from the S-boxes is then permuted using a predefined table (P) - Transposition
        - The P output is XORed with LPT to produce the new RPT for the next round
        - The RPT from the previous round becomes the new LPT for the next round
     4. Final Permutation (IP^-1)
     - After 16 rounds, the final LPT and RPT are combined and passed through the inverse of the initial permutation (IP^-1) to produce the final ciphertext
     - IP^-1 rearranges the bits back to their original positions, reversing the IP
     - The output of IP^-1 is the final 64-bit ciphertext resulting from the DES encryption process
     5. The same process is used for decryption, but the subkeys are applied in reverse order (starting from K16 down to K1)
 */
public class DES {

    private final static int[] PC1 =
            {
                    57, 49, 41, 33, 25, 17,  9,
                    1, 58, 50, 42, 34, 26, 18,
                    10,  2, 59, 51, 43, 35, 27,
                    19, 11,  3, 60, 52, 44, 36,
                    63, 55, 47, 39, 31, 23, 15,
                    7, 62, 54, 46, 38, 30, 22,
                    14,  6, 61, 53, 45, 37, 29,
                    21, 13,  5, 28, 20, 12,  4
            };

    // How many positions to shift for each of the 16 rounds
    private final static int[] KEY_SHIFTS = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

    private final static int[] PC2 =
            {
                    14, 17, 11, 24, 1, 5,
                    3, 28, 15, 6, 21, 10,
                    23, 19, 12, 4, 26, 8,
                    16, 7, 27, 20, 13, 2,
                    41, 52, 31, 37, 47, 55,
                    30, 40, 51, 45, 33, 48,
                    44, 49, 39, 56, 34, 53,
                    46, 42, 50, 36, 29, 32
            };


    static final int[] IP =
            {
                    58, 50, 42, 34, 26, 18, 10, 2,
                    60, 52, 44, 36, 28, 20, 12, 4,
                    62, 54, 46, 38, 30, 22, 14, 6,
                    64, 56, 48, 40, 32, 24, 16, 8,
                    57, 49, 41, 33, 25, 17, 9, 1,
                    59, 51, 43, 35, 27, 19, 11, 3,
                    61, 53, 45, 37, 29, 21, 13, 5,
                    63, 55, 47, 39, 31, 23, 15, 7
            };

    private static final int[] e =
            {
                    32,  1,  2,  3,  4,  5,
                    4,  5,  6,  7,  8,  9,
                    8,  9, 10, 11, 12, 13,
                    12, 13, 14, 15, 16, 17,
                    16, 17, 18, 19, 20, 21,
                    20, 21, 22, 23, 24, 25,
                    24, 25, 26, 27, 28, 29,
                    28, 29, 30, 31, 32,  1
            };

    private static final int[][] s1 = {
            {14, 4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
            {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11,  9,  5,  3,  8},
            {4, 1, 14,  8, 13,  6, 2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
            {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
    };

    private static final int[][] s2 = {
            {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
            {3, 13,  4, 7, 15,  2,  8, 14, 12,  0, 1, 10,  6,  9, 11,  5},
            {0, 14, 7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
            {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14,  9}
    };

    private static final int[][] s3 = {
            {10, 0, 9, 14, 6, 3, 15, 5,  1, 13, 12, 7, 11, 4, 2,  8},
            {13, 7, 0, 9, 3,  4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
            {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14,  7},
            {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
    };

    private static final int[][] s4 = {
            {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
            {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14,  9},
            {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
            {3, 15, 0, 6, 10, 1, 13, 8, 9,  4, 5, 11, 12, 7, 2, 14}
    };

    private static final int[][] s5 = {
            {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
            {14, 11, 2, 12,  4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
            {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
            {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
    };

    private static final int[][] s6 = {
            {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
            {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
            {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
            {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
    };

    private static final int[][] s7 = {
            {4, 11, 2, 14, 15,  0, 8, 13 , 3, 12, 9 , 7,  5, 10, 6, 1},
            {13 , 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
            {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
            {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
    };

    private static final int[][] s8 = {
            {13, 2, 8,  4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
            {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6 ,11, 0, 14, 9, 2},
            {7, 11, 4, 1, 9, 12, 14, 2,  0, 6, 10 ,13, 15, 3, 5, 8},
            {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6 ,11}
    };

    private static final int[][][] S_BOXES = {s1, s2, s3, s4, s5, s6, s7, s8};

    static int[] p =
            {
                    16,  7, 20, 21,
                    29, 12, 28, 17,
                    1, 15, 23, 26,
                    5, 18, 31, 10,
                    2,  8, 24, 14,
                    32, 27,  3,  9,
                    19, 13, 30,  6,
                    22, 11,  4, 25
            };

    static int[] IPi =
            {
                    40, 8, 48, 16, 56, 24, 64, 32,
                    39, 7, 47, 15, 55, 23, 63, 31,
                    38, 6, 46, 14, 54, 22, 62, 30,
                    37, 5, 45, 13, 53, 21, 61, 29,
                    36, 4, 44, 12, 52, 20, 60, 28,
                    35, 3, 43 ,11, 51, 19, 59, 27,
                    34, 2, 42, 10, 50, 18, 58, 26,
                    33, 1, 41, 9, 49, 17, 57, 25
            };

    private final String[] subkeys = new String[16];

    private long[] K;

    static void main() {
        DES des = new DES();

        String testKey = "133457799BBCDFF1";
        String testPlaintext = "0123456789ABCDEF";

        System.out.println("--- STARTING DES TEST ---");
        System.out.println("Plaintext (Hex): " + testPlaintext);
        System.out.println("Key (Hex):       " + testKey);

        des.generateSubkeys(testKey);
        String ciphertext = des.encryptBlock(testPlaintext);

        String plainText = des.decryptBlock(binToHex(ciphertext));

        System.out.println("\n--- FINAL RESULT ---");
        System.out.println("Calculated Ciphertext: " + binToHex(ciphertext));
        System.out.println("Expected Ciphertext:   85E813540F0AB405");
        System.out.println("Calculated Plain: " + binToHex(plainText));
        System.out.println("Expected Plaintext:   0123456789ABCDEF");

    }

    public String encryptBlock(String hexData) {
        // Initial Permutation (IP)
        String binData = hexToBin64(hexData);
        String permutedData = performPermutation(binData, IP);
        System.out.println("After IP: " + permutedData);

        // Split into L and R
        String L = permutedData.substring(0, 32);
        String R = permutedData.substring(32);

        // 16 Rounds
        for (int i = 0; i < 16; i++) {
            String previousR = R;
            String fResult = feistelFunction(R, subkeys[i]);

            R = xor(L, fResult);
            L = previousR;

            System.out.printf("Round %2d: L=%s, R=%s%n", (i + 1), binToHex(L), binToHex(R));
        }

        // Final Swap and Inverse IP (IP^-1)
        String combined = R + L;
        return performPermutation(combined, IPi);
    }

    public String decryptBlock(String hexCiphertext) {
        // Initial Permutation (IP)
        String binData = hexToBin64(hexCiphertext);
        String permutedData = performPermutation(binData, IP);

        // Split into L and R
        String L = permutedData.substring(0, 32);
        String R = permutedData.substring(32);

        // 16 Rounds with Keys in REVERSE
        for (int i = 15; i >= 0; i--) {
            String previousR = R;
            String fResult = feistelFunction(R, subkeys[i]);

            R = xor(L, fResult);
            L = previousR;
        }

        // Final Swap and Inverse IP (IP^-1)
        String combined = R + L;
        return performPermutation(combined, IPi);
    }

    public String feistelFunction(String R, String key) {
        // Expansion (32 -> 48 bits)
        String expandedR = performPermutation(R, e);

        // XOR with Subkey
        String xorResult = xor(expandedR, key);

        // S-Box Substitution (48 -> 32 bits)
        String substituted = substituteSBox(xorResult);

        System.out.println("S-Box Output (Hex): " + binToHex(substituted));

        // P-Permutation (32 -> 32 bits)
        return performPermutation(substituted, p);
    }

    public String substituteSBox(String input48) {
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            // Get 6-bit chunk
            String chunk = input48.substring(i * 6, (i + 1) * 6);

            // Row: First and last bit
            int row = Integer.parseInt("" + chunk.charAt(0) + chunk.charAt(5), 2);
            // Col: Middle 4 bits
            int col = Integer.parseInt(chunk.substring(1, 5), 2);

            // Look up in S-box and get the value
            int val = S_BOXES[i][row][col];

            // Convert to 4-bit binary
            String bin4 = Integer.toBinaryString(val);
            while (bin4.length() < 4) bin4 = "0" + bin4;
            output.append(bin4);
        }
        return output.toString();
    }

    public static String xor(String a, String b) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < a.length(); i++) {
            sb.append(a.charAt(i) == b.charAt(i) ? "0" : "1");
        }
        return sb.toString();
    }

    public void generateSubkeys(String hexKey) {
        String binKey = hexToBin64(hexKey);
        System.out.println("Original Key (Bin): " + binKey);

        // PC-1 Permutation
        String key56 = performPermutation(binKey, PC1);
        System.out.println("Key after PC-1 (56 bits): " + key56);

        // Split into C and D (28 bits each)
        String C = key56.substring(0, 28);
        String D = key56.substring(28);
        System.out.println("C0: " + C);
        System.out.println("D0: " + D);

        // Generate 16 subkeys
        System.out.println("\n--- Generating 16 Subkeys ---");
        for (int i = 0; i < 16; i++) {
            // 1. Shift both halves
            C = leftShift(C, KEY_SHIFTS[i]);
            D = leftShift(D, KEY_SHIFTS[i]);

            // Combine and Permute via PC-2
            String combined = C + D;
            subkeys[i] = performPermutation(combined, PC2);

            System.out.printf("Round %2d: K = %s (Hex: %s)%n",
                    (i + 1), subkeys[i], binToHex(subkeys[i]));
        }
    }

    // Performs a circular left shift on a bit string
    public static String leftShift(String input, int step) {
        String shifted = input.substring(step) + input.substring(0, step);
        return shifted;
    }

    public static String performPermutation(String input, int[] table) {
        StringBuilder output = new StringBuilder();
        for (int position : table) {
            output.append(input.charAt(position - 1));
        }
        return output.toString();
    }

    // Converts Hex String to exactly 64-bit Binary String
    public static String hexToBin64(String hex) {
        StringBuilder bin = new StringBuilder();
        for (char c : hex.toUpperCase().toCharArray()) {
            int val = Character.digit(c, 16);
            String b = Integer.toBinaryString(val);
            while (b.length() < 4) b = "0" + b; // Pad each hex char to 4 bits
            bin.append(b);
        }
        // If hex was too short, pad leading zeros to reach 64 bits
        while (bin.length() < 64) bin.insert(0, "0");
        return bin.toString();
    }

    // Converts Binary String to Hex String
    public static String binToHex(String bin) {
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < bin.length(); i += 4) {
            String chunk = bin.substring(i, i + 4);
            int decimal = Integer.parseInt(chunk, 2);
            hex.append(Integer.toHexString(decimal).toUpperCase());
        }
        return hex.toString();
    }

    public static String utfToBinary(String input) {
        byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
        StringBuilder binary = new StringBuilder();
        for (byte b : bytes) {
            String s = Integer.toBinaryString(b & 0xFF);
            binary.append(String.format("%8s", s).replace(' ', '0'));
        }
        return binary.toString();
    }

    public static String binaryToUtf(String binary) {
        byte[] bytes = new byte[binary.length() / 8];
        for (int i = 0; i < bytes.length; i++) {
            String chunk = binary.substring(i * 8, (i + 1) * 8);
            bytes[i] = (byte) Integer.parseInt(chunk, 2);
        }
        return new String(bytes, StandardCharsets.UTF_8);
    }

}