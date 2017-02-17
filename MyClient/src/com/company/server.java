package com.company;

import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.Data;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.SecureRandom;

public class server {


    public static void main(String[] args) throws Exception {


//
//        if (args.length != 2) {
//            System.err.println("First Argument Should ");
//        } else {
//
//        }
//        SecureRandom randomSecureRandom = SecureRandom.getInstance("SHA1PRNG");
//        byte[] iv = new byte[16];
//        randomSecureRandom.nextBytes(iv);
//
//        String IV = DatatypeConverter.printBase64Binary(iv);
//        String key = "1234567890abcdef";
//
//        MyAES myAES = new MyAES(key, IV);

        Socket s = new Socket((String) null, 9090);
        BufferedReader input =
                new BufferedReader(new InputStreamReader(s.getInputStream()));

        String msg = input.readLine();
        String IV = msg.substring(0,15);
        System.out.println("IV received: " +IV);
//        String original = myAES.decrypt(answer);
//        System.out.println("Message Received: " + original);
        System.exit(0);
    }

}
