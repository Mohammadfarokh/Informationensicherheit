package com.example.cryptography;

import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;

public class Test {
    public static void main(String[] args) throws Exception {
       /*  AesEncryption a = new AesEncryption("PKCS7Padding", "CTR");
         SecretKey aesKey = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f"), "AES");
        byte[] iv = Hex.decode("bbaa99887766554433221100");
        byte[] msg = Strings.toByteArray("hello, world!");
        byte[] aad = Strings.toByteArray("now is the time!");
        System.out.println("msg : " + Hex.toHexString(msg));
        byte[] cText = ccmEncryptWithAAD(aesKey, iv, msg, aad);
        System.out.println("cText: " + Hex.toHexString(cText));
        byte[] pText = ccmDecryptWithAAD(aesKey, iv, cText, aad);
        System.out.println("pText: " + Hex.toHexString(pText));
         byte[] eText= a.encryptGCM("hello");
        byte[] dText = a.decryptGCM(); */

       /* Security.addProvider(new BouncyCastleProvider());

        Provider[] providers = Security.getProviders();

        for (Provider provider : providers) {
            System.out.println(provider.getName());
        }
        SecretKey aesKey = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f"), "AES");
        AlgorithmParameterGenerator pGen =AlgorithmParameterGenerator.getInstance("GCM","BC");
        byte[] msg = Strings.toByteArray("hello, world!");
        System.out.println("msg : " + Hex.toHexString(msg));
        AlgorithmParameters pGCM = pGen.generateParameters();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, pGCM); //<<<
        byte[] cText = cipher.doFinal(msg);
        System.out.println("cText: " + Hex.toHexString(cText));
        GCMParameterSpec gcmSpec = pGCM.getParameterSpec(GCMParameterSpec.class); // done
        byte[] pText = gcmDecrypt(aesKey, gcmSpec.getIV(), gcmSpec.getTLen(), cText);//<<<
        System.out.println("pText: " + Hex.toHexString(pText)); */
    }

    static byte[] gcmDecrypt(SecretKey key,byte[] iv,int tagLen,byte[] cText)throws Exception{
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        GCMParameterSpec spec = new GCMParameterSpec(tagLen, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(cText);
    }

    public static byte[] ccmEncryptWithAAD(SecretKey key, byte[] nonce, byte[] pText, byte[] aData)throws Exception{
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", "BC");
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        cipher.updateAAD(aData);
        return cipher.doFinal(pText);
    }

    public static byte[] ccmDecryptWithAAD(SecretKey key, byte[] nonce, byte[] cText, byte[] aData)throws Exception{
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", "BC");
        AEADParameterSpec spec = new AEADParameterSpec(nonce, 128, aData);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(cText);
    }
    }

