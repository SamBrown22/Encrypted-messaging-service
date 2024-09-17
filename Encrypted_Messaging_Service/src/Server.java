import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class Server {
    //SECRET STRING FOR HASHING
    private static final String SECRET_STRING = "gfhk2024:";

    // DECLARE STORAGE
    private Map<String, List<Message>> messages;

    // INITIALISE STORAGE ON SERVER CREATION
    private Server() {
        this.messages = new HashMap<>();
    }

    // CHECKS ARGUMENTS ARE CORRECT ON SERVER START
    public static void main(String[] args) {

        // Checks to see if the command has the correct amount of arguments
        if (args.length != 1) {
            System.out.println("Usage: java Server port");
            System.exit(1);
        }

        // Create a server and Runs server
        Server server = new Server();
        server.run(args);

    }

    // START SERVER AND HANDLE CONNECTIONS
    private void run(String[] args){

        // Assigns the port argument to a variable 'port'
        int port = Integer.parseInt(args[0]);

        try {
            // Creates a new server socket using the port number
            ServerSocket serverSocket = new ServerSocket(port);
            System.out.println("Server is listening on port " + port);

            while (true) {
                // Wait for a client to connect
                System.out.println("Waiting for a client to connect... \n");
                Socket clientSocket = serverSocket.accept();

                // Call a method to handle this client
                handleClient(clientSocket);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // HANDLE CLIENT REQUESTS
    private void handleClient(Socket clientSocket) throws IOException {
        try {
            ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
            ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());

            // Read hashed userid from client and show login in console
            String hashedUserId = (String) in.readObject();
            System.out.println(hashedUserId + " has logged in.");

            /**
             *
             * CHECK FOR MESSAGES AND SEND TO USER
             * (CHECKS NO. MESSAGES FOR USER USING USER ID)
             *
             **/

            // Check saved messages for this user
            int numberOfMessages = countMessages(hashedUserId);
            List<Message> awaitingMessages = retrieveMessages(hashedUserId);

            // Send number of messages for this user
            out.writeInt(numberOfMessages);
            out.flush();

            // Console show number of messages for this user
            System.out.println("Delivering " +numberOfMessages+ " message(s) ...");

            //If number of messages isn't 0
            if (numberOfMessages != 0){
                for (int i=0; i < numberOfMessages; i++){

                    // For each message in the users list create a signature and send to user
                    Message message = awaitingMessages.get(i);
                    byte[] messageSig = createSignature(message.getContent(), message.getTimestamp());

                    out.write(messageSig);
                    out.writeObject(message);
                    out.flush();
                }
            }

            /**
             *
             * RECEIVING MESSAGES FROM USER
             * (READ IN SIGNATURE, MESSAGE AND USERID / VERIFY SIGNATURE USING USER'S PUB KEY AND MESSAGE CONTENTS)
             * !IF SIGNATURE DOESNT VERIFY OR SENDER UNRECOGNISED(NO KEY) THE MESSAGE IS DISCARDED!
             *
             **/

            // Receive message(contents, including message and recipient, and timestamp) from target user
            byte[] signature = in.readAllBytes();
            Message serverEncryptedMessage = (Message) in.readObject();
            String user = in.readUTF();

            try{
                // If verification of signature fails - TERMINATE(dont continue)
                verifySignature(user, serverEncryptedMessage.getContent(), serverEncryptedMessage.getTimestamp(), signature);

            }
            catch(SignatureException e){
                System.out.println("");
                System.out.println("VERIFICATION FAILED");
                in.close();
                out.close();
                clientSocket.close();
                return;
            }

            // If sender not recognised - TERMINATE(dont continue)
            catch (NoSuchFileException e){
                System.out.println("");
                System.out.println("SENDER NOT RECOGNISED");
                in.close();
                out.close();
                clientSocket.close();
                return;
            }

            catch (Exception e){
                e.printStackTrace();
                return;
            }

            /**
             *
             * IF SIGNATURE VERIFIED - DECRYPTING, ENCRYPTING AND STORING MESSAGE
             * (DECRYPT MESSAGE AND SPLIT CONTENTS TO GET RECIPIENT USER ID / ENCRYPT MESSAGE, WITHOUT CONCAT USERID,
             * AND STORE WITH HASHED USERID)
             * !IF DECRYPTION FAILS DISCARD THE MESSAGE!
             *
             **/

            // Initialise variable to store decrypted message
            String serverDecryptedMessage = null;

            // Try to Decrypt and save to variable
            try{
                serverDecryptedMessage = RSADecryptIncoming(serverEncryptedMessage.getContent());
            }
            // If decryption fails - TERMINATE(dont continue)
            catch(BadPaddingException e){
                System.out.println("");
                System.out.println("DECRYPTION FAILED");
                return;
            }

            // Find the recipient and message from the decrypted contents
            String recipient  = serverDecryptedMessage.split("&")[0];
            String DecryptedMessage = serverDecryptedMessage.split("&")[1];

            //Console log the message contents
            System.out.println("incoming message from " +user);
            System.out.println(serverEncryptedMessage.getTimestamp());
            System.out.println("recipient: " +recipient);
            System.out.println("message: " +DecryptedMessage+ "\n");

            // Initialise variable to store encrypted message
            byte[] encryptedMessage = null;

            // Try to Encrypt message with recipient public key
            try{
                encryptedMessage = RSAEncryptOutgoing(DecryptedMessage, recipient+".pub");
            }

            // Cannot encrypt as no recipient public key found - TERMINATE(dont continue)
            catch (NoSuchFileException e){
                System.out.println("");
                System.out.println("RECIPIENT KEY NOT FOUND");
                return;
            }

            // Create new message using the target user public key encrypted message and the unencrypted timestamp from previous message
            Message clientEncryptedMessage = new Message(encryptedMessage, serverEncryptedMessage.getTimestamp());

            // Store Message which hashed the recipient and stores the hashed ID and message to the Hashmap
            storeMessage(recipient, clientEncryptedMessage);

            in.close();
            out.close();
            clientSocket.close();
        }
        catch(SocketException|EOFException e){
            System.out.println("Client Disconnected");
        }
        catch(Exception e){
            e.printStackTrace();
        }
    }

    // STORE MESSAGE IN HASHMAP
    private void storeMessage(String recipient, Message message) throws NoSuchAlgorithmException {
        String hashRecipient = hashUserId(recipient);

        // Check if there is an existing user in Store
        if (messages.containsKey(hashRecipient)){
            //If yes, add the message to their message list-
            messages.get(hashRecipient).add(message);
        }
        else{
            // If no, create a new message list under the new recipient id
            List<Message> messageList = new ArrayList<>();
            messageList.add(message);
            messages.put(hashRecipient, messageList);
        }
    }

    // RETRIEVE LIST OF MESSAGES IN STORAGE FOR USER AND DELETES
    private List<Message> retrieveMessages(String user){
        if(messages.containsKey(user)){
            List<Message>userMessages = messages.get(user);

            messages.remove(user);
            return userMessages;
        }
        else {
            return null;
        }
    }

    // COUNT MESSAGES IN STORAGE FOR USER
    private Integer countMessages(String user){
        if (messages.containsKey(user)){
            int numberOfMessages = messages.get(user).size();
            return numberOfMessages;
        }
        else return 0;
    }

    // HASH STRING
    private String hashUserId(String userid) throws NoSuchAlgorithmException {
        // Get an instance of the MD5 message digest algorithm
        MessageDigest MD5 = MessageDigest.getInstance("MD5");

        // Create a String from the secret string and the user id
        String user = SECRET_STRING+userid;

        // Convert the string to a byte array and update the MD5 digest
        byte [] Bytes = user.getBytes();
        MD5.update(Bytes);

        // Obtain the MD5 hash as an array of bytes
        byte[] MD5HashBytes = MD5.digest();

        // Convert the hash bytes to a hexadecimal string
        StringBuilder MD5HashHex = new StringBuilder();
        for (byte b : MD5HashBytes){
            MD5HashHex.append(String.format("%02X", b));
        }

        // Return the Hexadecimal representation of the MD5 hashed string
        return MD5HashHex.toString();
    }

    // DECRYPT WITH SERVER PRIVATE KEY
    private String RSADecryptIncoming(byte[] encryptedData) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //Get server private key
        File file = new File("server.prv");
        byte[] privateKeyBytes = Files.readAllBytes(file.toPath());
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] decryptedBytes = cipher.doFinal(encryptedData);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    // ENCRYPT WITH USER PUBLIC KEY (ONLY CAN BE DECRYPTED WITH PRIVATE)
    private byte[] RSAEncryptOutgoing(String data, String keyFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //Get the public key of the client
        File file = new File(keyFile);
        byte[] publicKeyBytes = Files.readAllBytes(file.toPath());
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    private byte[] createSignature(byte[] outgoingData, Date timestamp) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        // Get the server's private key from a file
        File file = new File("server.prv");
        byte[] privateKeyBytes = Files.readAllBytes(file.toPath());

        // Convert the key byte array to a private key
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        // Create a signature object using the SHA256withRSA algorithm
        Signature signature = Signature.getInstance("SHA256withRSA");

        // Initialize the signature object with the server's private key
        signature.initSign(privateKey);

        // Update the signature object with the outgoing data and timestamp
        signature.update(outgoingData);
        signature.update(timestamp.toString().getBytes());

        // Generate and return the digital signature
        return signature.sign();
    }

    private boolean verifySignature(String user, byte[] incomingData, Date incomingTimestamp, byte[] messageSignature) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        // Get the user's public key from a file
        File file = new File(user + ".pub");
        byte[] publicKeyBytes = Files.readAllBytes(file.toPath());

        // Convert the byte array to a public key
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        // Create a signature object using the SHA256withRSA algorithm
        Signature signature = Signature.getInstance("SHA256withRSA");

        // Initialize the signature object with the user's public key
        signature.initVerify(publicKey);

        // Update the signature object with the incoming data
        signature.update(incomingData);
        signature.update(incomingTimestamp.toString().getBytes());

        // Verify the signature against the provided message signature
        boolean result = signature.verify(messageSignature);

        return result;
    }
}
