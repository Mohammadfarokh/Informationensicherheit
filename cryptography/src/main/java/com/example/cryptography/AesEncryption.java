package com.example.cryptography;

import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.Base64;



public class AesEncryption {

    private SecretKey secretKey;
    private String paddingMethod;
    private String blockModes;
    private IvParameterSpec ivParameterSpec;
    private AlgorithmParameters pGCM;
    private AlgorithmParameterGenerator pGen;
    private GCMParameterSpec gcmSpec;
    private  byte[] msg;
    private  byte[] cText;
    private PBEParameterSpec pbeSpec;
    private byte[] iv;
    private  byte[] aData;





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
            System.out.println("Please save your IV =" + ivParameterSpec.toString());
            System.out.println("My Text length is =" + plainText.length());
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    /** sd
     * Decrypts the provided Base64-encoded encrypted text using AES decryption.
     * @param encryptedText The Base64-encoded encrypted text
     * @return The decrypted plaintext
     */

    public String decrypt(String encryptedText) {
        try {
            Cipher cipher = Cipher.getInstance("AES/"+ blockModes+"/" + paddingMethod,"BC");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            System.out.println("your Key is =" + secretKey.toString());
            System.out.println("Please save your IV =" + ivParameterSpec.toString());
            System.out.println("My Text length is =" + encryptedText.length());
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
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

    public byte[] encryptGCM(String plainText) throws Exception {
        secretKey = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f"), "AES");
        pGen =AlgorithmParameterGenerator.getInstance("GCM","BC");
        msg = Strings.toByteArray(plainText);
        pGCM = pGen.generateParameters();
        gcmSpec = pGCM.getParameterSpec(GCMParameterSpec.class);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC"); // back to org
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, pGCM);
        cText = cipher.doFinal(msg);
        System.out.println("from inside ecryptGCM : " + Hex.toHexString(cText));
        return cText;
    }

    public byte[] decryptGCM() throws Exception {
        secretKey = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f"), "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        GCMParameterSpec spec = new GCMParameterSpec(gcmSpec.getTLen(), gcmSpec.getIV());
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        System.out.println("from inside decryptGCM : " + Hex.toHexString(cText));
        return cipher.doFinal(cText);
    }
    public byte[] ccmEncryptWithAAD(byte[] pText)throws Exception{
        secretKey = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f"), "AES");
        iv = Hex.decode("bbaa99887766554433221100");
        aData = Strings.toByteArray("now is the time!");
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", "BC");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        cipher.updateAAD(aData);
        return cipher.doFinal(pText);
    }

    public byte[] ccmDecryptWithAAD( byte[] cText)throws Exception{
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", "BC");
        AEADParameterSpec spec = new AEADParameterSpec(iv, 128, aData);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        return cipher.doFinal(cText);
    }

    public byte[] encryptWithPasswordAES256GCMScrypt(String plainText, String password) throws Exception {
        // Generate a key using SCrypt from the provided password
        byte[] keyBytes = SCrypt.generate(password.getBytes(), "salt".getBytes(), 16384, 8, 1, 32); // Adjust parameters as needed
        secretKey = new SecretKeySpec(keyBytes, "AES");

        // Perform GCM encryption
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());

        return encryptedBytes;
    }

    public String decryptWithPasswordAES256GCMScrypt(byte[] encryptedBytes, String password) throws Exception {
        // Generate a key using SCrypt from the provided password
        byte[] keyBytes = SCrypt.generate(password.getBytes(), "salt".getBytes(), 16384, 8, 1, 32); // Adjust parameters as needed
        secretKey = new SecretKeySpec(keyBytes, "AES");

        // Perform GCM decryption
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes);
    }

    public byte[] encryptWithPasswordPBEWithSHA256And128BitAESCBCBC(String plainText, String password) throws Exception {
        // Generate a key using PBE with SHA256 and 128-bit AES-CBC
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWithSHA256And128BitAES-CBC-BC");
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), "salt".getBytes(), 65536, 128); // Adjust parameters as needed
        SecretKey tmp = factory.generateSecret(keySpec);
        secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

        // Perform AES-CBC encryption
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, pbeSpec);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());

        return encryptedBytes;
    }

    public String decryptWithPasswordPBEWithSHA256And128BitAESCBCBC(byte[] encryptedBytes, String password) throws Exception {
        // Generate a key using PBE with SHA256 and 128-bit AES-CBC
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWithSHA256And128BitAES-CBC-BC");
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), "salt".getBytes(), 65536, 128); // Adjust parameters as needed
        SecretKey tmp = factory.generateSecret(keySpec);
        secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

        // Perform AES-CBC decryption
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, pbeSpec);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes);
    }

    public byte[] encryptWithPasswordPBEWithSHAAnd40BitRC4(String plainText, String password) throws Exception {
        // Generate a key using PBE with SHA and 40-bit RC4
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWithSHAAnd40BitRC4");
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), "salt".getBytes(), 65536, 40); // Adjust parameters as needed
        SecretKey tmp = factory.generateSecret(keySpec);
        secretKey = new SecretKeySpec(tmp.getEncoded(), "RC4");

        // Perform RC4 encryption
        Cipher cipher = Cipher.getInstance("RC4");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());

        return encryptedBytes;
    }

    public String decryptWithPasswordPBEWithSHAAnd40BitRC4(byte[] encryptedBytes, String password) throws Exception {
        // Generate a key using PBE with SHA and 40-bit RC4
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWithSHAAnd40BitRC4");
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), "salt".getBytes(), 65536, 40); // Adjust parameters as needed
        SecretKey tmp = factory.generateSecret(keySpec);
        secretKey = new SecretKeySpec(tmp.getEncoded(), "RC4");

        // Perform RC4 decryption
        Cipher cipher = Cipher.getInstance("RC4");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes);
    }


}

