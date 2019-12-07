package com.encrypt.sample.helper;

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
 * 3DES对称加密算法
 */
public class TripleDes {
    public static byte[] generateKey() {
        byte[] key = null;
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
            //DES是一个基于56位密钥的对称的加密算法,而3DES其实是进行3次DES。
            keyGenerator.init(56 * 3);
            key = keyGenerator.generateKey().getEncoded();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return key;
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
            SecretKey secretKey = new SecretKeySpec(key, "DESede");
            //算法参数，增加加密算法的强度
            IvParameterSpec ivParameterSpec = new IvParameterSpec(key);
            Cipher cipher = Cipher.getInstance("DESede");
            cipher.init(opmode, secretKey, ivParameterSpec);
            bytes = cipher.doFinal(data);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        return bytes;
    }
}
