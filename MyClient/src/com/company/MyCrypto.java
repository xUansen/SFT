package com.company;

/**
 * Created by xuanhe on 15/02/2017.
 */
public interface MyCrypto {
    String encrypt(String plaintext) throws Exception;
    String decrypt(String ciphertext) throws Exception;
}
