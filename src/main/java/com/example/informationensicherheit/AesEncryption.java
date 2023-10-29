package com.example.informationensicherheit;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

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
    private IvParameterSpec ivParameterSpec;

    public AesEncryption(String paddingMethod) throws NoSuchAlgorithmException {
        Security.setProperty("crypto.policy", "unlimited");
        Security.addProvider(new BouncyCastleProvider());
        int maxKeySize = Cipher.getMaxAllowedKeyLength("AES");
        System.out.println("Max Key Size for AES : " + maxKeySize);
        this.paddingMethod = paddingMethod;
        generateKey();
        initializeIV();
    }

    public void generateKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES","BC");
            keyGenerator.init(256); // You can choose 128, 192, or 256 bits
            secretKey = keyGenerator.generateKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String encrypt(String plainText) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/" + paddingMethod,"BC");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            System.out.println("Please save your Key =" + secretKey.toString());
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public String decrypt(String encryptedText) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/" + paddingMethod,"BC");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private void initializeIV() {
        // Generate a random IV (Initialization Vector)
        byte[] iv = new byte[16]; // AES block size is 16 bytes
        new SecureRandom().nextBytes(iv);
        ivParameterSpec = new IvParameterSpec(iv);
    }
}

