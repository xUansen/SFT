package com.company;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.nio.charset.Charset;

/**
 * Created by xuanhe on 15/02/2017.
 */
public class MyAES  {

    private String key;
    private String IV;

    public MyAES(String key, String IV) {
        this.key = key;
        this.IV = IV;
    }

    public MyAES() {

    }

    //    @Override
    public String encrypt(String plaintext) throws Exception {

        try {
            byte[] iv = this.IV.getBytes();
            System.out.println(iv.length);
            IvParameterSpec ivParams = new IvParameterSpec(iv);
            SecretKeySpec secretKeySpec = new SecretKeySpec(this.key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParams);

            byte[] encrypted = cipher.doFinal(plaintext.getBytes());

            System.out.println("encrypted string: "
                    + DatatypeConverter.printBase64Binary(encrypted));

            return DatatypeConverter.printBase64Binary(encrypted);

        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

//    @Override
    public String decrypt(String ciphertext) throws Exception {

        try {
            IvParameterSpec iv = new IvParameterSpec(IV.getBytes("UTF-8"));
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);
            byte[] original = cipher.doFinal(DatatypeConverter.parseBase64Binary(ciphertext));

            return new String(original);

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }
}
