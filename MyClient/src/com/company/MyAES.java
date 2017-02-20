package com.company;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

/**
 * Created by xuanhe on 15/02/2017.
 */
public class MyAES {

    private String key;
    private byte[] IV;
    private String algorithm;

    public MyAES(String key, byte[] IV) {
        this.key = key;
        this.IV = IV;
    }

    public  MyAES() {}

    public void setIV(byte[] IV) {
        this.IV = IV;
    }

    public String encrypt(String plaintext) throws Exception {

        byte[] iv = this.IV;

        IvParameterSpec ivParams = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(this.key.getBytes("UTF-8"), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParams);

        byte[] encrypted = cipher.doFinal(plaintext.getBytes());


        return Base64.getEncoder().encodeToString(encrypted);

    }

    public String decrypt(String ciphertext) throws Exception {

        IvParameterSpec iv = new IvParameterSpec(this.IV);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);
        byte[] original = cipher.doFinal(Base64.getDecoder().decode(ciphertext));

        return new String(original);

    }
}
