# Project Overview
This project is assignment from COMS4180 Network Security Spring 2017. In this project, there is a regular socket communication between the client and server. 
The client encrypts and sign a file, then send an encrypted key, the encrypted file and the signature to the server. The server decrypts the file, checks the signature and indicates whether the signature verification failed or passed. 
However, there is no assumption that the server will only receive messages from the client. The server may have malware on it that may sometimes replaces the encrypted file with another file. 

.
├── app  
|   └── source code for client and server
├── client_keys
|   └── RSA Key pair for client
├── server_keys
|   └── RSA Key pair for server
├── test_files
|   └── files that client uses to encrypt 
├── client.sh
├── server.sh
├── README.md
└── compileApp.sh


# Project Details
The client and server have RSA keys (using 2048 bit modulus) that will be used in this process.  A command line argument given to the server will indicate if the file is replaced.
After receiving the message from client, the server will write the message to *receivedMsg* the current directory . Depending on mode, server will either use the received file or use *fakefile* to perform decryption and verification.

## RSA Key Generation
The 2048 bit RSA key pair are generated before running the client and server application, by issuing the following command.
```
openssl genrsa -out [private_key].pem 2048
```
```
openssl pkcs8 -topk8 -inform PEM -outform DER -in [private_key].pem -out [private_key name].der -nocrypt
```
```
openssl rsa -in [private_key].pem -pubout -outform DER -out [public_key name].der
```
The above steps will be run twice to generate client's public private key pair and server's public private key pair.
The two key pairs are in two different folders, `client_keys` and `server_keys`. Feel free to generate your own but rememebr to place them in the correct folder.

## Preparation
Before run the application, there are certain inputs which will be prepared by the user:
- The file to be encrypted and signed. 
 * Place the files under the folder test_files 
 * Unfortunately, the applications only plain txt file or binary readable file
- Your own 16 character password. 
 * This will be used as a input when running client app in command line.
 * Password is case sensitive and alphanumeric, but cannot contain any special characters.

## Usage

- Compile server and client app in shell
```
bash server.sh
```
or
```
javac app/client.java
javac app/server.java
```

- Open server app by running `bash server.sh` (example input are provided). The parameters are specified as follows:
 * port number
 * mode: 'u' for untrusted mode, 't' for trusted mode
 * server private key .der type file: file name
 * client public key .der file name: file name
  
- Open client app by running `bash client.sh`. The parameters are specified as follows:
 * user chosen password: 16 character alphanumeric password
 * File to be encrypted and signed: file should be under test_files directory, don't specify path
 * IP address of server: in the format of "255.255.255.255"
 * port number
 * client private key .der type file: file name
 * server public key .der type file: file name
