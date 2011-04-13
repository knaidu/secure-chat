import java.io.PrintWriter;
import java.io.OutputStreamWriter;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.Socket;
import java.util.Random;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.net.InetAddress;
public class Client {
    
    public Socket serverSocket;
    public static int serverPort;
    public static String serverName;
    public static Socket s;
    public static PrintWriter out;
    public static BufferedReader in;
    public static String serverReply;
    public static String initialString;
    public static MyThread reader;
    public static MyThread writer;
    public static BufferedWriter fout;
    public static int sessionID;
    public static int serverRandno;
    public static int clientRandno;
    public static String sessionKey;
    public static CryptoSuite.CRYPTO_SUITE crypto = CryptoSuite.CRYPTO_SUITE.NONE;
    
    public static final String CLIENT_MSG = "CLIENT MSG:";
    public static final String SERVER_MSG = "SERVER MSG:";
    
    public Client() {
    }
    public static int getRandomNumber(){
        Random rand=new Random();
        return rand.nextInt(12345);
    }
    public static void clientHello(){
        try {
            //sends a hello msg to server, msg includes random number + list of ciphers supported
            clientRandno = getRandomNumber();
            if (sessionID == 0) {
                initialString= clientRandno +" Cipher1 Cipher2 Cipher3 Cipher4";
                fout.append(CLIENT_MSG+ "[Ciphers, R{Alice}]-> " + initialString + "\n");
            } else {
                initialString= clientRandno +" Cipher1 Cipher2 Cipher3 Cipher4 " + sessionID;
                fout.append(CLIENT_MSG+ "[Ciphers, R{Alice} sessionID]-> " + initialString + "\n");
            }
            boolean retValue = CryptoSuite.writeSocket(s,initialString,
                        CryptoSuite.cryptoType.NONE);
            // Log the message.
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    /**
     * This function is used to store the client sessionID and validate the server
     * certificate. It also sends the client secret and Keyed hash of the 
     * handshake message to the server.
     */    
    public static boolean clientKeyExchange(String handshakeMsg) {
        try {
            boolean retValue = false;
            if (sessionID == 0) {
                // Message is of the form sessionID server-certificate server-randno crypto.
                String msg = handshakeMsg;
                String msgSubstr[] = msg.split(" ");
                // Store the sessionID
                sessionID = Integer.parseInt(msgSubstr[0]);
                fout.append("[CLIENT ACTION]-> Storing the session-id:" + sessionID + "\n" );
                // Validate the server certificate.
                int cert = CryptoSuite.verifyCertificate(msgSubstr[1].getBytes());
                fout.append("[CLIENT ACTION] -> Validating the server certificate:");
                //if (Server.DEBUG)
                    System.out.println("received certificate:" + cert);
                if (cert == CryptoSuite.E) {
                    fout.append("Server certificate is valid. Server's public key " +
                            " can be used for sending the shared secret.\n");
                } else {
                    fout.append("Server certificate is invalid. Bailing out.");
                    // Return failure.
                    return false;
                }
                // Store the server random number.
                serverRandno = Integer.parseInt(msgSubstr[2]);
                //if (Server.DEBUG)
                    System.out.println("Got Server's random number:" + serverRandno);
                fout.append("[CLIENT ACTION] -> Storing server's random number:" + serverRandno + "\n");    

                // Store the selected crypto algo.
                int option = Integer.parseInt(msgSubstr[3]);
                switch (option) {
                    case 1:
                        crypto = CryptoSuite.CRYPTO_SUITE.DES3_CBC;
                        break;
                    case 2:
                        crypto = CryptoSuite.CRYPTO_SUITE.DES3_PCBC;
                        break;
                    case 3:
                        crypto = CryptoSuite.CRYPTO_SUITE.DES_CFB;
                        break;
                    case 4:
                        crypto = CryptoSuite.CRYPTO_SUITE.RC4;
                        break;
                    case 0:
                    default:
                        crypto = CryptoSuite.CRYPTO_SUITE.NONE;
                }                
                
                //crypto = Integer.parseInt(msgSubstr[3]);

                byte[] sharedSecret = String.valueOf(CryptoSuite.SHARED_SECRET).getBytes();
                // Client computes the encrypted shared secret by encrypting the
                // shared secret using server's public key.
                String encSharedSecret = new String(CryptoSuite.encodeRSACipher(sharedSecret,
                        CryptoSuite.E, CryptoSuite.N));
                System.out.println("enc shared secret:" + encSharedSecret);

                sessionKey = CryptoSuite.calculateKey(CryptoSuite.SHARED_SECRET,
                        clientRandno, serverRandno);
                fout.append("[CLIENT ACTION]-> Calculating the session key 'K' " + 
                        sessionKey + " using secret " +
                        CryptoSuite.SHARED_SECRET + " client random no." + clientRandno +
                        " and server random number " + serverRandno + "\n");
                // Initialize the DES and Keyed hash.
                CryptoSuite.initDESKeys(sessionKey);
                fout.append("[CLIENT ACTION] -> Using the session key 'K' " + sessionKey +
                        " to compute the secret keys needed for the encryption and hash " +
                        " algorithm.\n");

                String hashHandshakeMsg = CryptoSuite.getRC4Cipher(handshakeMsg);
                // Send the result back to the Server.
                String clientKeyMsg = encSharedSecret + " " + hashHandshakeMsg;
                retValue = CryptoSuite.writeSocket(s, clientKeyMsg,
                        CryptoSuite.cryptoType.NONE);
                // Log the message in the client log.
                //fout.append(clientKeyMsg + "\n");
                fout.append(CLIENT_MSG + "P{Bob}[S], K(keyed hash of messages)-> " +
                        clientKeyMsg + "\n");

                // Get the keyed hash message from the server.
                serverReply = CryptoSuite.readFromSocket(s, CryptoSuite.cryptoType.NONE);
                if (serverReply.compareTo(CryptoSuite.END_BLK) == 0)
                    return retValue;
                System.out.println("hash handshake message from server:" + serverReply);
                fout.append(SERVER_MSG + "k(keyed hash of messages)-> " +
                        serverReply + "\n");
            } else {
                // Message is of the form sessionID keyed_hash_of_msg server-randno crypto.
                String msg = handshakeMsg;
                String msgSubstr[] = msg.split(" ");
                // Store the sessionID
                sessionID = Integer.parseInt(msgSubstr[0]);
                fout.append("[CLIENT ACTION]-> Verifying the session-id:" + sessionID + "\n" );
                // Store the server random number.
                serverRandno = Integer.parseInt(msgSubstr[2]);
                fout.append("[CLIENT ACTION] -> Storing server's random number:" + serverRandno + "\n");
                String hashMsg = msgSubstr[3];
                fout.append("[CLIENT ACTION] -> Getting the hash value:" + hashMsg );
                int option = Integer.parseInt(msgSubstr[3]);
                switch (option) {
                    case 1:
                        crypto = CryptoSuite.CRYPTO_SUITE.DES3_CBC;
                        break;
                    case 2:
                        crypto = CryptoSuite.CRYPTO_SUITE.DES3_PCBC;
                        break;
                    case 3:
                        crypto = CryptoSuite.CRYPTO_SUITE.DES_CFB;
                        break;
                    case 4:
                        crypto = CryptoSuite.CRYPTO_SUITE.RC4;
                        break;
                    case 0:
                    default:
                        crypto = CryptoSuite.CRYPTO_SUITE.NONE;
                }                
                
                // Calculating the sessionKey
                sessionKey = CryptoSuite.calculateKey(CryptoSuite.SHARED_SECRET,
                        clientRandno, serverRandno);
                fout.append("[CLIENT ACTION]-> Calculating the session key 'K' " + 
                        sessionKey + " using secret " +
                        CryptoSuite.SHARED_SECRET + " client random no." + clientRandno +
                        " and server random number " + serverRandno + "\n");
                // Initialize the DES and Keyed hash.
                CryptoSuite.initDESKeys(sessionKey);
                fout.append("[CLIENT ACTION] -> Using the session key 'K' " + sessionKey +
                        " to compute the secret keys needed for the encryption and hash " +
                        " algorithm.\n");                
                // Send the Keyed hash message to the server.
                retValue = CryptoSuite.writeSocket(s, hashMsg, CryptoSuite.cryptoType.NONE);
            }
          // Return success.
          return retValue;
        } catch (Exception e) {
            e.printStackTrace();
        }
        // Return failure.
        return false;
    }
    
    public static void main(String[] args){
        try{
            // Initialize the sessionID.
            sessionID = 0;
            serverPort = 9876;        

            // Check the for loop braces.
            for (int i = 0; i < 4; i++) {
                System.out.println("************** Secure chat: CLIENT SIDE.********************");
                System.out.println("***** 3DES/CBC, 3DES/PCBC, DES/CFB - Privacy protection*****");
                System.out.println("*******************RC4- Integrity protection.****************");
                System.out.println("**** Enter 'quit' to exit from the program. *****************");
                
                boolean retVal = Util.readConfigurationFile();
                if (!retVal) {
                    System.err.println("Client: Error in reading the configuration file.");
                    System.exit(-1);
                }
                if (Util.isMTMEnabled) {
                    serverName = Util.mtmHost;
                } else {
                    serverName = Util.serverName;
                }
            
                fout=new BufferedWriter(new FileWriter("Client.txt",true));
                s = new Socket(serverName,serverPort);
            
                fout.append("CLIENT LOG\n");
                fout.append("CLIENT HOSTNAME: "+InetAddress.getLocalHost().getHostName() + "\n");
            
                reader = new MyThread("reader",s,fout,"Client",null);
                writer = new MyThread("writer",s,fout,"Client",null);
            
                //Session initiatiation
                //Send R-server and ciphers
                //PROTOCOL
                clientHello();
                do {
                    serverReply = CryptoSuite.readFromSocket(s, CryptoSuite.cryptoType.NONE);
                } while (serverReply.compareTo(CryptoSuite.END_BLK) == 0);
                
                System.out.println("Initial Server reply: "+serverReply);
                //fout.append("CLIENT ID: "+serverReply.substring(0,1)+"\n");
                fout.append(SERVER_MSG + "[Session-ID, my certificate," +
                        " cipher, R{Bob}]-> " + serverReply + "\n");
            
                // Send the client key exchange information. The handshake message is sent.
                retVal = clientKeyExchange(serverReply);
                if (!retVal) {
                    fout.append("Client: Error in client key exchange.\n");
                    fout.close();
                    // Close the socket.
                    s.close();
                    // Return exit status.
                    System.exit(-1);
                }
            
                //Then start reader and writer threads
                fout.close();                
                reader.start();
                writer.start();
                reader.join();
                writer.join();
                s.close();
                
                Thread.sleep(25000);
            }
        }
        catch(Exception e) {
            e.printStackTrace();
        }
    }
}