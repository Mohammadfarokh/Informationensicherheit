package com.example.cryptography;
import org.bouncycastle.util.encoders.Hex;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.util.Base64;

public class HashingComponent {
    private static final String SHA_256 = "SHA-256";
    private static final String HMAC_SHA_256 = "HmacSHA256";
    private static SecretKeySpec secretKey;

    public static String generateSHA256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA_256);
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String generateHMACSHA256(String input) {
        try {
            Mac hmacSha256 = Mac.getInstance(HMAC_SHA_256);
            secretKey = new SecretKeySpec(Hex.decode("2ccd85dfc8d18cb5d84fef4b198554699fece6e8692c9147b0da983f5b7bd413"), HMAC_SHA_256);
            hmacSha256.init(secretKey);
            byte[] hash = hmacSha256.doFinal(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }


    public static boolean verifyHash(String input, String hash, String algorithm) {
        switch (algorithm) {
            case SHA_256:
                return hash.equals(generateSHA256(input));
            case HMAC_SHA_256:
                return hash.equals(generateHMACSHA256(input));
            default:
                return false;
        }
    }
}

