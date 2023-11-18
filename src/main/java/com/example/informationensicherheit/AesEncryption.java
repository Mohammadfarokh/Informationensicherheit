package com.example.informationensicherheit;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;



public class AesEncryption {

    private SecretKey secretKey;
    private String paddingMethod;
    private String blockModes;
    private IvParameterSpec ivParameterSpec;



    /**
     * Constructs an AesEncryption instance with the specified padding method.
     * Initializes the Bouncy Castle provider and sets up the encryption key and IV.
     * @param paddingMethod The padding method to be used (e.g., "PKCS7Padding")
     * @throws NoSuchAlgorithmException Thrown when a cryptographic algorithm is not available
     */
    public AesEncryption(String paddingMethod, String blockModes) throws NoSuchAlgorithmException {
        Security.setProperty("crypto.policy", "unlimited");
        Security.addProvider(new BouncyCastleProvider());
        int maxKeySize = Cipher.getMaxAllowedKeyLength("AES");
        System.out.println("Max Key Size for AES : " + maxKeySize);
        this.paddingMethod = paddingMethod;
        this.blockModes = blockModes;
        generateKey();
        initializeIV();
    }




    /**
     * Generates a random secret key for AES encryption.
     */
    public void generateKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES","BC");
            keyGenerator.init(256); // You can choose 128, 192, or 256 bits
            secretKey = keyGenerator.generateKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    /**
     * Encrypts the provided plaintext using AES encryption.
     * @param plainText The plaintext to be encrypted
     * @return The Base64-encoded encrypted text
     */
    public String encrypt(String plainText) {
        try {
            Cipher cipher = Cipher.getInstance("AES/"+ blockModes+"/" + paddingMethod,"BC");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            System.out.println("Please save your Key =" + secretKey.toString());
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    /**
     * Decrypts the provided Base64-encoded encrypted text using AES decryption.
     * @param encryptedText The Base64-encoded encrypted text
     * @return The decrypted plaintext
     */
    public String decrypt(String encryptedText) {
        try {
            Cipher cipher = Cipher.getInstance("AES/"+ blockModes+"/" + paddingMethod,"BC");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Generates a random initialization vector (IV) for AES encryption.
     * The IV is used to provide an additional layer of security to the encryption process.
     */
    private void initializeIV() {
        // Generate a random IV (Initialization Vector)
        byte[] iv = new byte[16]; // AES block size is 16 bytes
        new SecureRandom().nextBytes(iv);
        ivParameterSpec = new IvParameterSpec(iv);
    }


}

