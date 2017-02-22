package app;


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
 * @author xuanhe
 */

public class MyRSA {

    private  String algorithm;


    public MyRSA(String algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * Generate private key from .der file content based on algorithm
     * 
     * @param filename: private key .der file name
     * @return PrivateKey: PKCS8 Private Key
     * @throw: Exception
     */

    public  PrivateKey getPemPrivateKey(String filename, String algorithm)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] content = Files.readAllBytes(Paths.get(filename));

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(content);
        KeyFactory kf = KeyFactory.getInstance(algorithm);

        return kf.generatePrivate(spec);
    }


    /**
     * Generate public key from .der file content based on algorithm
     * 
     * @param filename: public key .der file name
     * @return Public key instance
     * @throw: Exception
     */
    public PublicKey  getPemPublicKey(String filename, String algorithm)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] content = Files.readAllBytes(Paths.get(filename));

        X509EncodedKeySpec spec = new X509EncodedKeySpec(content);
        KeyFactory kf = KeyFactory.getInstance(algorithm);

        return kf.generatePublic(spec);
    }

    // Compute message digest routine, using SHA256

    private byte[] computeMsgDigest(String plaintext) throws NoSuchAlgorithmException {

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(plaintext.getBytes());

        byte[] byteData = md.digest();

        return byteData;
    }


    // Encrypt file using public key so that someone who has private key can decrypt

    public String encrypt(String plaintext, PublicKey publicKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(this.algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes());

        return Base64.getEncoder().encodeToString(encrypted);

    }

    // Decrypt file using private key return decrypted text

    public String decrypt(String ciphertext, PrivateKey privateKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(this.algorithm);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(ciphertext));

        return new String(decrypted);
    }

    //Sign text using one's private key, following compute hash of text, encrypt hash using pub key routine.

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
