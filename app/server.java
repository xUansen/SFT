package app;


import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/**
 * @author Xuan He
 *
 */

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
        Base64.Encoder myEncoder = Base64.getEncoder();
        Base64.Decoder myDecoder = Base64.getDecoder();


        int portNumber;
        String client_pubKey_filename;
        String server_priKey_filename;
        ServerSocket myListener;
        boolean mode;

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
            myListener = new ServerSocket(portNumber);
            System.out.println("Trying to establish connection");
        } catch (IOException e) {
            System.err.println("Error: Cannot open port" + usage);
            return;
        }

        String mode_input = args[1];
        switch (mode_input) {
            case "u":
                mode = true;
                System.out.println("We are in untrusted mode");
                break;
            case "t":
                mode = false;
                System.out.println("We are in trusted mode");
                break;
            default:
                System.err.println("Error: mode input is invalid" + usage);
                return;
        }

        boolean b = false;

        try {
            while (true) {

                try (Socket mySocket = myListener.accept()) {
                    System.out.println("Connection established");

                    BufferedReader input =
                            new BufferedReader(new InputStreamReader(mySocket.getInputStream()));

                    String msg = new String();

                    String[] submsg = new String[4];

                    if (mode == false) {
                        msg = input.readLine();

                    } else {
                        msg = new String(Files.readAllBytes(Paths.get("fakefile")), "UTF-8");
                        if (msg.length() <= 712) {
                            System.err.println("Fake File Detected, Length Incorrect");
                            return;
                        }
                    }

                    submsg[0] = msg.substring(0, 24);
                    submsg[1] = msg.substring(24, 368);
                    submsg[2] = msg.substring(368, 712);
                    submsg[3] = msg.substring(712);

                    byte[] IV = myDecoder.decode(submsg[0]);

//                    System.out.println("IV \n"+ submsg[0]);
//                    System.out.println("Encrypted Password\n" + submsg[1]);
//                    System.out.println("Signature\n" + submsg[2]);
//                    System.out.println("File\n" + submsg[3]);

                    String password = myRSA.decrypt(submsg[1], server_prikey);
                    MyAES myAES = new MyAES(password, IV);

                    String originalText = myAES.decrypt(submsg[3]);

                    b = myRSA.verify(submsg[2], originalText, client_pubkey);

                    System.out.println("Trying to write decrypted message to file");

                    Files.write(Paths.get("decryptedfile"),
                            originalText.getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE);
                    System.out.println("Decrypted message is written to file name \'decryptedfile\'");
                    break;

                } catch (IOException e) {
                    System.err.println("Can not write to file");
                } catch (InvalidKeyException e) {
                    System.err.println("Connection cannot be established");
                } catch (NoSuchAlgorithmException e) {
                    System.err.println("Crypto Algorithm is invalid");
                } catch (BadPaddingException e) {
                    System.err.println("Bad Padding Detected from Cipher text, Malware may be existent");
                } catch (IllegalBlockSizeException e) {
                    System.err.println("Block size is illegal, Malware may be existent");
                } catch (NoSuchPaddingException e) {
                    System.err.println("No such Padding algorithm");
                } finally {

                    if (b) {
                        System.out.println("Verification Passed ! Phew");
                    } else {
                        System.out.println("Verification Failed");
                    }

                    System.out.println("Connection closed");
                }
            }
        } finally {
            myListener.close();

            System.out.println("Server listener closed");
        }


        System.exit(0);
    }

}
