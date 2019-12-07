package com.encrypt.sample.helper;

import android.util.Log;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * ChaCha20对称加密算法
 */
public class ChaCha20 {
    private static final String IPS = "abcdefabcdef";

    /**
     * 生成秘钥
     */
    public static byte[] generateKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("ChaCha20");
            keyGen.init(256);
            SecretKey secretKey = keyGen.generateKey();

            return secretKey.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * 加密
     */
    public static byte[] encrypt(byte[] data, byte[] key) {
        return doCipher(data, key, Cipher.ENCRYPT_MODE);
    }

    /**
     * 解密
     */
    public static byte[] decrypt(byte[] data, byte[] key) {
        return doCipher(data, key, Cipher.DECRYPT_MODE);
    }

    /**
     * 进行加密/解密
     *
     * @param data   原始数据
     * @param key    密钥
     * @param opmode 加密/解密{@link Cipher#ENCRYPT_MODE},{@link Cipher#DECRYPT_MODE}
     */
    private static byte[] doCipher(byte[] data, byte[] key, int opmode) {
        byte[] bytes = null;
        try {
            //这里首先将密钥字节流转为secret key
            SecretKey secretKey = new SecretKeySpec(key, "ChaCha20/CBC/PKCS5Padding");

            //算法参数，增加加密算法的强度
            IvParameterSpec ivParameterSpec = new IvParameterSpec(IPS.getBytes());

            Cipher cipher = Cipher.getInstance("ChaCha20");
            cipher.init(opmode, secretKey, ivParameterSpec);
            bytes = cipher.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        return bytes;
    }
}
