package com.encrypt.sample.helper;

/**
 * XOR加密算法
 */
public class Xor {
    private Xor() {
    }

    public static byte[] execute(byte[] data, int key) {
        if (data == null || data.length == 0) {
            return null;
        }

        int length = data.length;

        for (int i = 0; i < length; i++) {
            data[i] ^= key;
        }

        return data;
    }
}
