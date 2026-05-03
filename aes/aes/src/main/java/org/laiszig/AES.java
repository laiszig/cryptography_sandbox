package org.laiszig;

import javax.crypto.*;
import java.util.Base64;
import java.util.Scanner;

/*
  128bit key AES Implementation
  * Creation of Round Keys - 4x4 table of hex bytes
  - 1st column - take last column from previous table - shift rows + substitute bytes from S-box + xor with 1st column
  - 2nd/3rd/4th column - take current 1st/2nd/3rd column - xor with 2nd/3rd/4th column from previous table
  * Encryption
  1. SubBytes
  - Each byte is substituted by another byte using S-box
  - A byte is never substituted by itself or compliment of current byte
  2. ShiftRows
  - 1st row is not shifted
  - 2nd row is shifted once to the left
  - 3rd row is shifted twice to the left
  - 4th row is shifted thrice to the left
  3. MixColumns
  - Matrix multiplication of current table with fixed matrix
  - This step is skipped in the last round
  4. AddRoundKey
  - Resultant output of previous stage is XORed with the corresponding round key.
*/
public class AES {

    private static final String ALGORITHM = "AES";

    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(128);
        return keyGen.generateKey();
    }

    public static String encrypt(String plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String ciphertext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] decoded = Base64.getDecoder().decode(ciphertext);
        byte[] decrypted = cipher.doFinal(decoded);

        return new String(decrypted);
    }

    static void main() throws Exception {

        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter plaintext: ");
        String plaintext = scanner.nextLine();

        SecretKey key = generateKey();

        System.out.println("Plaintext: " + plaintext);

        String encrypted = encrypt(plaintext, key);
        System.out.println("Ciphertext: " + encrypted);

        String decrypted = decrypt(encrypted, key);
        System.out.println("Decrypted: " + decrypted);

    }
}
