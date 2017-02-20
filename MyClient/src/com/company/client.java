package com.company;

import javax.crypto.*;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by xuanhe on 15/02/2017.
 */

public class client {
    private static byte[] generateIV() throws NoSuchAlgorithmException {
        SecureRandom randomSecureRandom = SecureRandom.getInstance("SHA1PRNG");

        byte[] iv = "1234567890abcdef".getBytes();
        randomSecureRandom.nextBytes(iv);

        return iv;
    }

    public static void main(String[] args) throws Exception {


        final String usage = "\nUsage: java client password file_to_be_encrypted server_IP port_number " +
                "client_private_key server_public_key\n" +
                "   password: 16 alphanumeric characters (case sensitive)\n" +
                "   file_to_be_encrypted : filename\n" +
                "   server_IP: following 255.255.255.255 format\n" +
                "   port_number: integer\n" +
                "   client_private_key: file name (Without path)\n" +
                "   server_public_key: file name (Without path)\n";

        Path currentRelativePath = Paths.get("");
        String curr_path = currentRelativePath.toAbsolutePath().toString();

        final String algorithm = "RSA";
        String client_priKey_filename;
        String server_pubKey_filename;
        int portNumber;
        int serverIP;

        MyRSA myRSA = new MyRSA(algorithm);


        // Handling input arguments
        if (args.length != 6) {
            System.err.println("Error: Missing Parameters" + usage);
            return;
        }


        //Only allow alphanumeric password
        String passwordInput = args[0];
        Pattern p = Pattern.compile("[^A-Za-z0-9]");
        Matcher m = p.matcher(passwordInput);
        boolean b = m.find();


        if (passwordInput.length() != 16 || b) {
            System.err.println("Error: password input format incorrect" + usage);
            return;
        }



        // Read in the file to be encrypted
        String plaintextFileName = args[1];

        String fileString = new String();

        try {
            fileString = new String(Files.readAllBytes(Paths.get(plaintextFileName)), "UTF-8");

        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return;
        }

        // Read in Port number and initializing port number
        try {
            portNumber = Integer.parseInt(args[3]);
        } catch (NumberFormatException e) {
            System.err.println("Error: port number is not valid, please input an integer" + usage);
            return;
        }

        ServerSocket myListener;
        try {
            myListener = new ServerSocket(portNumber);
        } catch (IOException e) {
            System.err.println("Error: Cannot open port" + usage);
            return;
        }


        // Construct server'public key and client's private key instances.
        client_priKey_filename = args[4];
        server_pubKey_filename = args[5];
        PrivateKey client_prikey;
        PublicKey server_pubkey;

        try {
            client_prikey = myRSA.getPemPrivateKey(curr_path + "/client_keys/" + client_priKey_filename, algorithm);
            server_pubkey = myRSA.getPemPublicKey(curr_path + "/server_keys/" + server_pubKey_filename, algorithm);
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }


        // Compute hash of the file and sign it using client private key
        String signature = myRSA.sign(fileString, client_prikey);

        // Encrypt shared key using server's public key so that only server can decrypt it
        String encryptedPassword = myRSA.encrypt(passwordInput, server_pubkey);


        // Encrypt the file using AES CBC mode using shared key and random IV
        byte[] iv = generateIV();
        MyAES myAES = new MyAES(passwordInput, iv);
        String encryptedFile = myAES.encrypt(fileString);

        Base64.Encoder myEncoder = Base64.getEncoder();
        Base64.Decoder myDecoder = Base64.getDecoder();

        System.out.println("signature length:" + signature.length());
        System.out.println(Base64.getDecoder().decode(signature).length);
        System.out.println("signature " + signature);


        String ivMsg = myEncoder.encodeToString(iv);

        System.out.println("IV length" + ivMsg.length());
        System.out.println("IV " + ivMsg);
        System.out.println("Password length" + Base64.getDecoder().decode(encryptedPassword).length);
        System.out.println("Password " + encryptedPassword);

        try {
            while (true) {
                Socket socket = myListener.accept();
                try {
                    PrintWriter out =
                            new PrintWriter(socket.getOutputStream(), true);
                    out.println(ivMsg+ encryptedPassword + signature+  encryptedFile);
                    break;
                } catch (Exception e) {
                    System.err.println("Connection cannot be established");
                } finally {
                    socket.close();
                }
            }
        } finally {
            myListener.close();
        }
    }


}
