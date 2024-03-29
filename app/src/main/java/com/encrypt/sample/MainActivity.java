package com.encrypt.sample;

import android.app.Activity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;

import com.encrypt.sample.helper.Aes;
import com.encrypt.sample.helper.ChaCha20;
import com.encrypt.sample.helper.Des;
import com.encrypt.sample.helper.TripleDes;
import com.encrypt.sample.helper.Hmac;
import com.encrypt.sample.helper.Rsa;
import com.encrypt.sample.helper.Sha;
import com.encrypt.sample.helper.Md5;
import com.encrypt.sample.helper.Rsa2;
import com.encrypt.sample.helper.Xor;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class MainActivity extends Activity {
    private final static String TAG = "EncryptSample";
    String inputClearText = "abc123456789中国人";
    String encryptKey = "key12345";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

    }

    public void testBase64(View view) {
        //Base64
        Log.d(TAG, "Base64编码结果：" + Base64.encodeToString(inputClearText.getBytes(), Base64.DEFAULT));
        Log.d(TAG, "自实现Base64编码结果：" + com.encrypt.sample.helper.Base64.encode(inputClearText.getBytes()));
        Log.d(TAG, "Base64反编码结果：" + new String(Base64.decode("YWJjMTIzNDU2Nzg55Lit5Zu95Lq6", Base64.DEFAULT)));
        Log.d(TAG, "自实现Base64反编码结果：" + new String(com.encrypt.sample.helper.Base64.decode("YWJjMTIzNDU2Nzg55Lit5Zu95Lq6")));
    }

    public void testMD5(View view) {
        //MD5
        Log.d(TAG, "MD5结果：" + Md5.MD5(inputClearText).toLowerCase());
    }

    public void testSHA(View view) {
        try {
            Log.d(TAG, "SHA1 encrypt: " + Sha.encrypt1(inputClearText));
            Log.d(TAG, "SHA224 encrypt: " + Sha.encrypt224(inputClearText));
            Log.d(TAG, "SHA256 encrypt: " + Sha.encrypt256(inputClearText));
            Log.d(TAG, "SHA384 encrypt: " + Sha.encrypt384(inputClearText));
            Log.d(TAG, "SHA512 encrypt: " + Sha.encrypt512(inputClearText));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void testHMAC(View view) {
        try {
            Log.d(TAG, "HMACMD5 encrypt: " + Hmac.encryptMD5(inputClearText.getBytes(), encryptKey.getBytes()));
            Log.d(TAG, "HMAC1 encrypt: " + Hmac.encrypt1(inputClearText.getBytes(), encryptKey.getBytes()));
            Log.d(TAG, "HMAC224 encrypt: " + Hmac.encrypt224(inputClearText.getBytes(), encryptKey.getBytes()));
            Log.d(TAG, "HMAC256 encrypt: " + Hmac.encrypt256(inputClearText.getBytes(), encryptKey.getBytes()));
            Log.d(TAG, "HMAC384 encrypt: " + Hmac.encrypt384(inputClearText.getBytes(), encryptKey.getBytes()));
            Log.d(TAG, "HMAC512 encrypt: " + Hmac.encrypt512(inputClearText.getBytes(), encryptKey.getBytes()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void testDES(View view) {
        try {
            byte[] key = Des.generateKey();
            //可以做到一次一密
            String base64Key = Base64.encodeToString(key, Base64.DEFAULT);
            Log.d(TAG, "key base64: " + base64Key);

            byte[] encryptData = Des.encrypt(inputClearText.getBytes(), Base64.decode(base64Key, Base64.DEFAULT));
            Log.d(TAG, "encrypt data base64: " + Base64.encodeToString(encryptData, Base64.DEFAULT));

            byte[] decryptData = Des.decrypt(encryptData, Base64.decode(base64Key, Base64.DEFAULT));
            Log.d(TAG, "decrypt data: " + new String(decryptData));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void test3DES(View view) {
        try {
            byte[] key = TripleDes.generateKey();
            String base64Key = Base64.encodeToString(key, Base64.DEFAULT);
            Log.d(TAG, "key base64: " + base64Key);

            byte[] encryptData = TripleDes.encrypt(inputClearText.getBytes(), Base64.decode(base64Key, Base64.DEFAULT));
            Log.d(TAG, "encrypt data base64: " + Base64.encodeToString(encryptData, Base64.DEFAULT));

            byte[] decryptData = TripleDes.decrypt(encryptData, Base64.decode(base64Key, Base64.DEFAULT));
            Log.d(TAG, "decrypt data: " + new String(decryptData));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void testAES(View view) {
        try {
            final byte[] key = Aes.generateKey();
            String base64Key = Base64.encodeToString(key, Base64.DEFAULT);
            Log.d(TAG, "key base64: " + base64Key);

            byte[] encryptData = Aes.encrypt(inputClearText.getBytes(), Base64.decode(base64Key, Base64.DEFAULT));
            Log.d(TAG, "encrypt data base64: " + Base64.encodeToString(encryptData, Base64.DEFAULT));

            byte[] decryptData = Aes.decrypt(encryptData, Base64.decode(base64Key, Base64.DEFAULT));
            Log.d(TAG, "decrypt data: " + new String(decryptData));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public void testChaCha20(View view) {
        try {
            byte[] key = ChaCha20.generateKey();
            String base64Key = Base64.encodeToString(key, Base64.DEFAULT);
            Log.d(TAG, "key base64: " + base64Key);

            byte[] encryptData = ChaCha20.encrypt(inputClearText.getBytes(), Base64.decode(base64Key, Base64.DEFAULT));
            Log.d(TAG, "encrypt data base64: " + Base64.encodeToString(encryptData, Base64.DEFAULT));

            byte[] decryptData = ChaCha20.decrypt(encryptData, Base64.decode(base64Key, Base64.DEFAULT));
            Log.d(TAG, "decrypt data: " + new String(decryptData));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void testRSA(View view) {
        byte[] data = inputClearText.getBytes();
        byte[] base64Data = Base64.encode(data, Base64.DEFAULT);

        Log.d(TAG, "原始数据长度： " + base64Data.length);

        KeyPair keyPair = Rsa.generateKeyPair(1024);

        byte[] publicKeyBase64Data = Base64.encode(keyPair.getPublic().getEncoded(), Base64.DEFAULT);
        byte[] privateKeyBase64Data = Base64.encode(keyPair.getPrivate().getEncoded(), Base64.DEFAULT);

        try {
            long start = System.currentTimeMillis();
            byte[] encryptData = Rsa.encryptWithPublicKeyBlock(base64Data, Base64.decode(publicKeyBase64Data, Base64.DEFAULT));
            Log.d(TAG, "公钥加密耗时: " + (System.currentTimeMillis() - start));
            Log.d(TAG, "公钥加密后密文: " + Base64.encodeToString(encryptData, Base64.DEFAULT));
            Log.d(TAG, "公钥加密后长度: " + encryptData.length);

            start = System.currentTimeMillis();
            byte[] decryptData = Rsa.decryptWithPrivateKeyBlock(encryptData, Base64.decode(privateKeyBase64Data, Base64.DEFAULT));
            Log.d(TAG, "私钥解密耗时: " + (System.currentTimeMillis() - start));

            Log.d(TAG, "私钥解密后长度: " + decryptData.length);
            Log.d(TAG, "私钥数据还原为：" + new String(Base64.decode(decryptData, Base64.DEFAULT)));

            Log.d(TAG, "==========================================================");

            encryptData = Rsa.encryptWithPrivateKeyBlock(base64Data, Base64.decode(privateKeyBase64Data, Base64.DEFAULT));
            Log.d(TAG, "私钥加密耗时: " + (System.currentTimeMillis() - start));
            Log.d(TAG, "私钥加密后密文: " + Base64.encodeToString(encryptData, Base64.DEFAULT));
            Log.d(TAG, "私钥加密后长度: " + encryptData.length);

            start = System.currentTimeMillis();
            decryptData = Rsa.decryptWithPublicKeyBlock(encryptData, Base64.decode(publicKeyBase64Data, Base64.DEFAULT));
            Log.d(TAG, "公钥解密耗时: " + (System.currentTimeMillis() - start));

            Log.d(TAG, "公钥解密后长度: " + decryptData.length);
            Log.d(TAG, "公钥数据还原为：" + new String(Base64.decode(decryptData, Base64.DEFAULT)));
        } catch (Exception e) {
            e.printStackTrace();
        }

        //Rsa
        KeyPair keyPair2 = Rsa2.generateRSAKeyPair(1024);
        PublicKey publicKey = keyPair2.getPublic();
        Rsa2.printPublicKeyInfo(publicKey);
        String e = Rsa2.encrypt(inputClearText, publicKey);
        Log.d(TAG, "RSA encrypt: " + e);
        PrivateKey privateKey = keyPair2.getPrivate();
        Rsa2.printPrivateKeyInfo(privateKey);
        String f = new String(Rsa2.decrypt(e, privateKey));
        Log.d(TAG, "RSA decrypt: " + f);
    }

    public void testXOR(View view) {
        try {
            int key = 0x00001111;

            byte[] encryptData = Xor.execute(inputClearText.getBytes(), key);
            Log.d(TAG, "encrypt data: " + new String(encryptData));
            Log.d(TAG, "encrypt data base64: " + Base64.encodeToString(encryptData, Base64.DEFAULT));

            byte[] decryptData = Xor.execute(encryptData, key);
            Log.d(TAG, "decrypt data: " + new String(decryptData));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


}
