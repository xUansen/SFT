package com.company;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

import javax.crypto.*;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Date;

/**
 * Created by xuanhe on 15/02/2017.
 */

public class client {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException,
            IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException,
            SignatureException, NoSuchProviderException {

        SecureRandom randomSecureRandom = SecureRandom.getInstance("SHA1PRNG");

        byte[] iv = "1234567890abcdef".getBytes();
        String IV = new String(iv, "utf-8");
        randomSecureRandom.nextBytes(iv);
//        String IV = Base64.encode(iv);

        ServerSocket listener = new ServerSocket(9090);
        System.out.println(IV);
        String key = "1234567890abcdef";

        MyAES myAES = new MyAES(key, IV);
        MyRSA myRSA = new MyRSA();

        myRSA.encrypt();
        System.out.println("IV sent: " + IV);
        try {
            while (true) {
                Socket socket = listener.accept();
                try {
                    PrintWriter out =
                            new PrintWriter(socket.getOutputStream(), true);
                    out.println(IV+myAES.encrypt(new Date().toString()));
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    socket.close();
                }
            }
        }
        finally {
            listener.close();
        }
    }


}
