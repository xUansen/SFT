package com.company;


import java.io.*;
import java.lang.reflect.Array;
import java.net.Socket;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;


public class server {


    public static void main(String[] args) throws Exception {

        final String usage = "\nUsage: java server Port_number mode server_private_key\n" +
                "   port_number: integer number\n" +
                "   mode : \n" +
                "      u: untrusted mode\n" +
                "      t: trusted mode\n" +
                "   server_private_key: file name (without path)\n" +
                "   client_public_key: file name (without path)";

        final Path currentRelativePath = Paths.get("");
        final String curr_path = currentRelativePath.toAbsolutePath().toString();
        final String algorithm = "RSA";

        int portNumber;
        String client_pubKey_filename;
        String server_priKey_filename;

        int mode;

        Socket mySocket = null;
        MyRSA myRSA = new MyRSA(algorithm);

        // Handling input arguments
        if (args.length != 4) {
            System.err.println("Error: Missing Parameters" + usage);
            return;
        }

        // Construct client's public key and server's private key
        client_pubKey_filename = args[3];
        server_priKey_filename = args[2];
        PublicKey client_pubkey;
        PrivateKey server_prikey;

        try {
            client_pubkey = myRSA.getPemPublicKey(curr_path + "/client_keys/" +
                    client_pubKey_filename, algorithm);
            server_prikey = myRSA.getPemPrivateKey(curr_path + "/server_keys/" +
                    server_priKey_filename, algorithm);
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }


        try {
            portNumber = Integer.parseInt(args[0]);
        } catch (NumberFormatException e) {
            System.err.println("Error: port number is not valid, please input an integer" + usage);
            return;
        }

        try {
            mySocket = new Socket((String) null, portNumber);
        } catch (IOException e) {
            System.err.println("Error: Cannot open port" + usage);
            return;
        }

        String mode_input = args[1];
        switch (mode_input) {
            case "u":
                mode = 1;
                break;
            case "t":
                mode = 0;
                break;
            default:
                System.err.println("Error: mode input is invalid" + usage);

        }
        Base64.Encoder myEncoder = Base64.getEncoder();
        Base64.Decoder myDecoder = Base64.getDecoder();

        BufferedReader input =
                new BufferedReader(new InputStreamReader(mySocket.getInputStream()));

        String msg = input.readLine();
        String[] submsg = msg.split("==");
        byte[] IV = myDecoder.decode(submsg[0]);

        String password = myRSA.decrypt(submsg[1], server_prikey);
        MyAES myAES = new MyAES(password, IV);

        String origintext = myAES.decrypt(submsg[3]);

//        System.out.println(origintext);
        boolean b = myRSA.verify(submsg[2], origintext, client_pubkey);

        System.out.println("Verify: "+ b);

//
//        byte[] iv = Arrays.copyOfRange(msgBytes,0,16);
//        byte[] pass = Arrays.copyOfRange(msgBytes,0,256);
//        byte[] sign = Arrays.copyOfRange(msgBytes,256, 512);
//        byte[] fileBytes = Arrays.copyOfRange(msgBytes,528, msgBytes.length);
//
//
////        String password = myRSA.decrypt(myEncoder.encodeToString(pass), server_prikey);
//        System.out.println("IV received: " + myEncoder.encodeToString(iv));
//        System.out.println("password: "+ myEncoder.encodeToString(pass));
//        System.out.println("sign " + myEncoder.encodeToString(sign));

        System.exit(0);
    }

}
