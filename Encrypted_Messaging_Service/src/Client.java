import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.Scanner;

public class Client {
    private static final String SECRET_STRING = "gfhk2024:";
    private Socket socket;
    private ObjectOutputStream out;
    private ObjectInputStream in;
    private String host;
    private int port;
    private String userid;

    // ARGUMENT CHECK
    public static void main(String[] args) {

        // Checks to see that there is the correct amount of arguments provided
        if (args.length != 3) {
            System.out.println("Usage: java Client host port userid");
            System.exit(1);
        }

        // Creates a new client object and calls run() to establish connection between client and server
        Client client = new Client();
        client.run(args);

    }

    // CLIENT-SERVER CONNECTION
    private void run(String[] args){

        /**
         *
         * HANDLES CLIENT-SERVER CONNECTION
         *
         **/

        // Assigns all the arguments to variables
        host = args[0];
        port = Integer.parseInt(args[1]);
        userid = args[2];

        try {
            socket = new Socket(host, port);
            out = new ObjectOutputStream(socket.getOutputStream());
            in = new ObjectInputStream(socket.getInputStream());
            System.out.println("Connected");

            //Send hashed userid to server
            String hashedUserId = hashUserId(userid);
            out.writeObject(hashedUserId);
            out.flush();

            // Store the Integer
            int numberOfMessages = in.readInt();

            // Call function to show the user messages and provide interface
            menu(userid, numberOfMessages);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // MAIN INTERFACE
    private void menu(String userid, int numberOfMessages) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, InvalidKeySpecException, BadPaddingException, InvalidKeyException, ClassNotFoundException, SignatureException {
        System.out.println("Client Program (user " + userid + ")");
        System.out.println("-------------------------");
        System.out.println("There are " + numberOfMessages + " messages for you.\n");

        /**
         *
         * RETRIEVAL OF MESSAGES
         * (VERIFY SIGNATURE, THEN DECRYPT AND READ TO USER)
         * !IF NOT VERIFIED TERMINATE CONNECTION!
         *
         **/

        if (numberOfMessages != 0) {
            for (int i = 0; i < numberOfMessages; i++) {

                // Read messages and there signatures one by one
                byte[] messageSignature = in.readAllBytes();
                Message message = (Message) in.readObject();

                try{
                    // Verify the signature to prove identity of each incoming message
                    if (verifySignature(message.getContent(), message.getTimestamp(), messageSignature)) {

                        //Decrypt and print the message and corresponding timestamp
                        System.out.println("Message: " + RSADecrypt(userid, message.getContent()));
                        System.out.println("Time: " + message.getTimestamp() + "\n");
                    }

                    // Not secure terminate connection
                    else {
                        in.close();
                        out.close();
                        socket.close();
                    }
                }
                catch (FileNotFoundException|NoSuchFileException e){
                    System.out.println("");
                    System.out.println("No file found");
                }
                catch(Exception e){
                 e.printStackTrace();
                }
            }
        }

        /**
         *
         *  SENDING MESSAGES
         *  (CONCATENATES AND ENCRYPTS RECIPIENT USER ID AND MESSAGE, THEN CREATES A SIGNATURE FROM THIS RESULT AND THE TIMESTAMP,
         *  THEN SENT TO SERVER WITH UNHASHED USERID)
         *  !IF NO END!
         *
         **/

        System.out.println("Do you want to send a message? (Y/N)");
        Scanner scanner = new Scanner(System.in);
        String answer = scanner.nextLine();

        // If no - TERMINATE
        if (answer.equals("N")) {
            in.close();
            out.close();
            socket.close();

        } else if (answer.equals("Y")) {
            System.out.println("");

            // Retrieves target recipient from client
            System.out.println("Enter the recipient User ID: ");
            String recipient = scanner.nextLine();

            // Retrieves the message for the recipient from client
            System.out.println("Enter your message: ");
            String userMessage = scanner.nextLine();

            try {
                // Concatenates the recipient and message and encrypts
                byte[] content = RSAEncrypt(recipient + "&" + userMessage);

                // Creates a timestamp with the message time when the message has been created
                Date timestamp = new Date();

                // Creates a message instance with content(recipient and message) and timestamp
                Message newMessage = new Message(content, timestamp);

                //Create signature using user private key
                byte[] messageSignature = createSignature(userid, content, timestamp);

            // Writes the message(content and timestamp) to server
            out.write(messageSignature);
            out.writeObject(newMessage);
            out.flush();

            // Sends unhashed userid to server can verify signature
            out.writeUTF(userid);
            out.flush();

            // Terminates program
            in.close();
            out.close();
            socket.close();
            }
            catch (FileNotFoundException|NoSuchFileException e){
                System.out.println("");
                System.out.println("No Key found to create signature");
            }
            catch(Exception e){
                e.printStackTrace();
            }
        }
    }

    // HASH A STRING
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

    // ENCRYPT A STRING USING PUB KEY (SO ONLY CAN BE DECRYPTED WITH CORRESPONDING PRV KEY)
    private byte[] RSAEncrypt(String data) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        File file = new File("server.pub");
        byte[] publicKeyBytes = Files.readAllBytes(file.toPath());
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

    }

    // DECRYPT A BYTE ARRAY WITH CORRECT USER PRV FILE
    private String RSADecrypt( String user, byte[] encryptedMessage) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        File file = new File(user + ".prv");
        byte[] privateKeyBytes = Files.readAllBytes(file.toPath());
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    // CREATE SIGNATURE FOR CLIENT VERIFICATION USING USER PRIVATE KEY
    private byte[] createSignature(String user, byte[] outgoingData, Date timestamp) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        // Get user's private key from a file
        File file = new File(user + ".prv");
        byte[] privateKeyBytes = Files.readAllBytes(file.toPath());

        // Convert the byte array to a private key
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        // Create a signature object using the SHA256withRSA algorithm
        Signature signature = Signature.getInstance("SHA256withRSA");

        // Initialize the signature object with the user's private key
        signature.initSign(privateKey);

        // Update the signature object with the outgoing data
        signature.update(outgoingData);
        signature.update(timestamp.toString().getBytes());

        // Generate and return the digital signature
        return signature.sign();
    }

    // VERIFY SERVER USING SERVER PUB KEY AND SENT CONTENTS
    private boolean verifySignature(byte[] incomingData,Date incomingTimestamp, byte[] messageSignature) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        // Get the user's public key from a file
        File file = new File("server.pub");
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
