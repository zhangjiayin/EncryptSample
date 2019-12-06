package com.encrypt.sample.helper;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * SHA消息摘要算法
 */
public class Sha {
    private Sha() {
    }

    public static String encrypt1(String data) {
        return encrypt(data, "Sha-1");
    }

    public static String encrypt224(String data) {
        return encrypt(data, "Sha-224");
    }

    public static String encrypt256(String data) {
        return encrypt(data, "Sha-256");
    }

    public static String encrypt384(String data) {
        return encrypt(data, "Sha-384");
    }

    public static String encrypt512(String data) {
        return encrypt(data, "Sha-512");
    }

    /**
     * 通过SHA加密
     *
     * @param data      原始数据
     * @param algorithm 算法(Sha-1，Sha-224，Sha-256，Sha-384，和SHA-512)
     */
    public static String encrypt(String data, String algorithm) {
        String result = null;

        try {
            byte[] dataBytes = data.getBytes();
            MessageDigest md5 = MessageDigest.getInstance(algorithm);
            md5.update(dataBytes);
            byte[] bytes = md5.digest();

            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                if (Integer.toHexString(0xFF & b).length() == 1) {
                    sb.append("0").append(Integer.toHexString(0xFF & b));
                } else {
                    sb.append(Integer.toHexString(0xFF & b));
                }
            }

            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return result;
    }
}
