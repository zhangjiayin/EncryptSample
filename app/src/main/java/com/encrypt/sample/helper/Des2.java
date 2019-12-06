package com.encrypt.sample.helper;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * DES对称加密算法-第2种实现
 */
public class Des2 {

    private byte[] iv;

    public Des2(byte[] iv) {
        super();
        this.iv = iv;
    }

    public static Des2 newInstance(byte[] iv) {
        Des2 des = new Des2(iv);
        return des;
    }

    public String encrypt(byte[] encryptByte, String encryptKey) {
        try {
            IvParameterSpec zeroIv = new IvParameterSpec(iv);
            SecretKeySpec key = new SecretKeySpec(encryptKey.getBytes(), "Des");
            Cipher cipher = Cipher.getInstance("Des/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, zeroIv);
            byte[] encryptedData = cipher.doFinal(encryptByte);
            return Base64.encode(encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] decrypt(String encryptString, String encryptKey) {
        try {
            byte[] encryptByte = Base64.decode(encryptString);
            IvParameterSpec zeroIv = new IvParameterSpec(iv);
            SecretKeySpec key = new SecretKeySpec(encryptKey.getBytes(), "Des");
            Cipher cipher = Cipher.getInstance("Des/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, zeroIv);
            return cipher.doFinal(encryptByte);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}