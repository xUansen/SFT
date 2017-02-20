package com.company;


import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


/**
 * Created by xuanhe on 16/02/2017.
 * http://codeartisan.blogspot.com/2009/05/public-key-cryptography-in-java.html
 */

public class MyRSA {

    private  String algorithm;


    public MyRSA(String algorithm) {
        this.algorithm = algorithm;
    }


    public  PrivateKey getPemPrivateKey(String filename, String algorithm)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] content = Files.readAllBytes(Paths.get(filename));
        PKCS8EncodedKeySpec spec =
                new PKCS8EncodedKeySpec(content);

        KeyFactory kf = KeyFactory.getInstance(algorithm);
        return kf.generatePrivate(spec);
    }

    public PublicKey  getPemPublicKey(String filename, String algorithm)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] content = Files.readAllBytes(Paths.get(filename));
        X509EncodedKeySpec spec =
                new X509EncodedKeySpec(content);

        KeyFactory kf = KeyFactory.getInstance(algorithm);
        return kf.generatePublic(spec);
    }

    public byte[] computeMsgDigest(String plaintext) throws NoSuchAlgorithmException {

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(plaintext.getBytes());
        byte[] byteData = md.digest();

        return byteData;
    }

    public String encrypt(String plaintext, PublicKey publicKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(this.algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes());
        System.out.println("RSA encrypt LENGHT " + encrypted.length);
        return Base64.getEncoder().encodeToString(encrypted);

    }

    public String decrypt(String ciphertext, PrivateKey privateKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(this.algorithm);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(ciphertext));

        return new String(decrypted);
    }

    public String sign(String plaintext, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException,
            NoSuchPaddingException, SignatureException, NoSuchProviderException {

        //Compute Message Digest
        byte[] digest = computeMsgDigest(plaintext);

        Cipher cipher = Cipher.getInstance(this.algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] signature = cipher.doFinal(digest);


        return Base64.getEncoder().encodeToString(signature) ;
    }

    public boolean verify(String signature, String original_text, PublicKey publicKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(this.algorithm);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] computeDigest = cipher.doFinal(Base64.getDecoder().decode(signature));

        byte[] digest = computeMsgDigest(original_text);

        return MessageDigest.isEqual(computeDigest, digest);
    }
}
