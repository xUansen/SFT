package app;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

/**
 * @author Xuan He
 */
public class MyAES {


    /**
     * Encrypt plain text using AES CBC and padding from Java Crypto library
     * Parameter IV is initialized and passed in from client
     * Parameter key is user-defined 16 character alphanumeric words
     * @param plaintext: original plain text to be encrypted
     * @return cipher text : String of cipher text
     * @throw: Exception
     */

    private String key;
    private byte[] IV;
    private String algorithm = "AES/CBC/PKCS5PADDING";


    public MyAES(String key, byte[] IV) {
        this.key = key;
        this.IV = IV;
    }

    public  MyAES() {}

    public void setIV(byte[] IV) {
        this.IV = IV;
    }

    /**
     * Encrypt plain text using AES CBC and padding from Java Crypto library
     * 
     * @param plaintext: original plain text to be encrypted
     * @return cipher text : String of cipher text
     * @throw: Exception
     */
    
    public String encrypt(String plaintext) throws Exception {

        byte[] iv = this.IV;

        IvParameterSpec ivParams = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(this.key.getBytes("UTF-8"), "AES");

        Cipher cipher = Cipher.getInstance(this.algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParams);


        byte[] encrypted = cipher.doFinal(plaintext.getBytes());


        return Base64.getEncoder().encodeToString(encrypted);

    }

    /**
     * Decrypt cipher text using AES CBC and padding from Java Crypto library
     * 
     * @param cipher text: string of cipher text
     * @return decrypted text : String of decrypted
     * @throw Exception
     */

    public String decrypt(String ciphertext) throws Exception {

        IvParameterSpec iv = new IvParameterSpec(this.IV);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

        Cipher cipher = Cipher.getInstance(this.algorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);

        byte[] original = cipher.doFinal(Base64.getDecoder().decode(ciphertext));

        return new String(original);

    }
}
