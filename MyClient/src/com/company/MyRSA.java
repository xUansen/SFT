package com.company;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;
import java.security.*;

/**
 * Created by xuanhe on 16/02/2017.
 */
public class MyRSA {

    public MyRSA() {

    }

    public String computeMsgDigest(String plaintext) throws NoSuchAlgorithmException {

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(plaintext.getBytes());
        byte[] byteData = md.digest();
        System.out.println("encrypted string: "
                + DatatypeConverter.printBase64Binary(byteData));
        return DatatypeConverter.printBase64Binary(byteData);
    }

    public void encrypt() throws NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException,
            NoSuchPaddingException, SignatureException, NoSuchProviderException {

        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        String plaintext = "This is the message being signed";

        PublicKey publicKey = keyPair.getPublic();


// Compute signature

        Signature instance = Signature.getInstance("SHA256withRSA");
        instance.initSign(privateKey);
        instance.update((plaintext).getBytes());
        byte[] signature = instance.sign();
        Signature sig = Signature.getInstance("SHA256withRSA");

        sig.initVerify(publicKey);
        sig.update(plaintext.getBytes());
        boolean verifies = sig.verify(signature);

// Compute digest
        MessageDigest sha1 = MessageDigest.getInstance("SHA-256");
        byte[] digest = sha1.digest((plaintext).getBytes());

// Encrypt digest
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] cipherText = cipher.doFinal(digest);

// Display results
        System.out.println("Input data: " + plaintext);
        System.out.println("Digest: " + DatatypeConverter.printBase64Binary(digest));
        System.out.println("Cipher text: " + DatatypeConverter.printBase64Binary(cipherText));
        System.out.println("Signature: " + DatatypeConverter.printBase64Binary(signature));



        System.out.println("Verified Signature: " + verifies);

        return;
    }

    public boolean verify(String signature) {

        return false;
    }
}
