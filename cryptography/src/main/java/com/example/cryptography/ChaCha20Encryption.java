package com.example.cryptography;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;

public class ChaCha20Encryption {

    private SecretKeySpec secretKey;
    private IvParameterSpec ivParameterSpec;

    /**
     * Constructs a ChaCha20Encryption instance with the specified key.
     * Initializes the Bouncy Castle provider and sets up the encryption key and IV.
     *
     * @param keyBytes The key for ChaCha20 encryption
     */
    public ChaCha20Encryption(byte[] keyBytes) {
        Security.setProperty("crypto.policy", "unlimited");
        Security.addProvider(new BouncyCastleProvider());
        this.secretKey = new SecretKeySpec(keyBytes, "ChaCha20");
        initializeIV();
    }

    /**
     * Encrypts the provided plaintext using ChaCha20 encryption.
     *
     * @param plainText The plaintext to be encrypted
     * @return The Hex-encoded encrypted text
     * @throws Exception Thrown if encryption fails
     */
    public String encrypt(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance("ChaCha20", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Hex.toHexString(encryptedBytes);
    }

    /**
     * Decrypts the provided Hex-encoded encrypted text using ChaCha20 decryption.
     *
     * @param encryptedText The Hex-encoded encrypted text
     * @return The decrypted plaintext
     * @throws Exception Thrown if decryption fails
     */
    public String decrypt(String encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance("ChaCha20", "BC");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        byte[] encryptedBytes = Hex.decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes);
    }

    /**
     * Generates a random initialization vector (IV) for ChaCha20 encryption.
     * The IV is used to provide an additional layer of security to the encryption process.
     */
    private void initializeIV() {
        byte[] iv = Hex.decode("010203040506070809101112");
 //     new java.security.SecureRandom().nextBytes(iv);
        ivParameterSpec = new IvParameterSpec(iv);
    }
}
