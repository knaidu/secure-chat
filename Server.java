import java.net.ServerSocket;
import java.net.Socket;
import java.io.PrintWriter;
import java.io.BufferedReader;
import java.io.BufferedOutputStream;
import java.io.BufferedInputStream;
import java.io.InputStreamReader;
import java.util.Random;
import java.io.OutputStreamWriter;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.net.InetAddress;
public class Server {
    //DECLARATIONS GO HERE..
    public static Boolean DEBUG;
    public static Boolean newConnections;
    public static ServerSocket serverSocket;
    public static int serverPort;
    public static int clientCount;
    public static Socket clientSocket;
    public static int MAX_CLIENTS;
    public static MyThread serviceThread;
    public static PrintWriter out;
    public static BufferedReader in;
    public static String clientReply;
    public static String initialReply;
    public static int sessionId;
    public static int sharedSecret;
    public static BufferedWriter fout;
    public static int clientRandno;
    public static int serverRandno;
    public static String sessionKey;
    
    public static CryptoSuite.CRYPTO_SUITE crypto = CryptoSuite.CRYPTO_SUITE.NONE;
    
    public static final String CLIENT_MSG = "CLIENT MSG:";
    public static final String SERVER_MSG = "SERVER MSG:";    
    
    public static int getRandomNumber(){
        Random rand=new Random();
        return rand.nextInt(1234567);
    }
    
    public static boolean serverHello(){
        boolean retValue = true;
        try {
            initialReply = CryptoSuite.readFromSocket(clientSocket, CryptoSuite.cryptoType.NONE);
            synchronized(fout) {
                fout=new BufferedWriter(new FileWriter("Server.txt",true));
                fout.append(CLIENT_MSG + "[Ciphers, R{Alice}]-> " + initialReply + "\n");
                fout.close();
            }
            // The handshake message is of the format:
            // clientRandno Cipher1 Cipher2 Cipher3 Cipher4
            String replySubstr[] = initialReply.split(" ");
            // Check whether the client already has session id.
            if (replySubstr.length == 5) {
                // Store the client's random number.
                clientRandno = Integer.parseInt(replySubstr[0]);
                synchronized (fout) {
                    fout=new BufferedWriter(new FileWriter("Server.txt",true));
                    fout.append("[SERVER ACTION] -> " + " Storing the client random number:"
                            + clientRandno + "\n");
                    fout.close();
                }

                if(DEBUG) System.out.println("reply: "+initialReply);
                // Chosen cipher is integer. Write now using CFB encryption.
                serverRandno = getRandomNumber();
                String cert = new String(CryptoSuite.getServerCertificate());
                synchronized (fout) {
                    fout=new BufferedWriter(new FileWriter("Server.txt",true));
                    fout.append("[SERVER ACTION] -> " + " Generating the session id:" + 
                            sessionId + "\n");
                    fout.append("[SERVER ACTION] -> " + " Getting the server's certificate:" +
                            cert + "\n");
                    fout.append("[SERVER ACTION] -> " + " Generating the server's random number:" +
                            serverRandno + "\n");
                    fout.close();
                }
                
                // Select the crypto to chose.
                int option = 0;
                do {
                    System.out.println("(0)None (1) 3DES/CBC (2) 3DES/PCBC (3) DES/CFB (4) RC4");
                    System.out.print("Which crypto do you want to use [0-4] ?");
                    BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
                    String chosenCipher = br.readLine();
                    option = Integer.parseInt(chosenCipher);
                } while ((option > 4) && (option <  0));
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
                String str  = sessionId + " "+  cert  + " " + serverRandno +" "+ option;
                retValue = CryptoSuite.writeSocket(clientSocket, str, CryptoSuite.cryptoType.NONE );
                synchronized(fout) {
                    fout=new BufferedWriter(new FileWriter("Server.txt",true));
                    fout.append(SERVER_MSG + "[Session-ID, Keyed hash of message," +
                        " cipher, R{Bob}]-> " + str + "\n");
                    fout.close();
                }
                
                // Perform client key Exchange.
                retValue = respondClientKeyExchange();
                if (!retValue) {
                    fout=new BufferedWriter(new FileWriter("Server.txt",true));
                    fout.append("Server: Error in client key exchange .\n");
                    fout.close();
                    return retValue;
                }
            } else {
                // The client is resuming his session.
                // Store the client's random number.
                clientRandno = Integer.parseInt(replySubstr[0]);
                synchronized (fout) {
                    fout=new BufferedWriter(new FileWriter("Server.txt",true));
                    fout.append("[SERVER ACTION] -> " + " Storing the client random number:"
                            + clientRandno + "\n");
                    fout.close();
                }
                serverRandno = getRandomNumber();
                synchronized (fout) {
                    boolean sessionValid = Integer.parseInt(replySubstr[5]) < sessionId ? true: false;
                    fout=new BufferedWriter(new FileWriter("Server.txt",true));
                    fout.append("[SERVER ACTION] -> " + " Verifying the session id:" + 
                            sessionValid + " Performing session resumption.\n");
                    fout.append("[SERVER ACTION] -> " + " Generating the server's random number:" +
                            serverRandno + "\n");
                    fout.close();
                }
                // Select the crypto to chose.
                int option = 0;
                do {
                    System.out.println("(0)None (1) 3DES/CBC (2) 3DES/PCBC (3) DES/CFB (4) RC4");
                    System.out.print("Which crypto do you want to use [0-4] ?");
                    BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
                    String chosenCipher = br.readLine();
                    option = Integer.parseInt(chosenCipher);
                } while ((option > 4) && (option < 0));
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
                // Compute the session key K.
                sessionKey = CryptoSuite.calculateKey(sharedSecret, clientRandno, serverRandno);
                synchronized(fout) {
                    fout=new BufferedWriter(new FileWriter("Server.txt",true));
                    fout.append("[SERVER ACTION] -> " + "Calculating the session key K:" + 
                            sessionKey + " using secret " + sharedSecret +
                            " client random number " + clientRandno + " server random number " +
                            serverRandno + "\n");
                    fout.close();
                }
                // Use the session key to generate the secret key and MAC.
                CryptoSuite.initDESKeys(sessionKey);
                synchronized(fout) {
                    fout=new BufferedWriter(new FileWriter("Server.txt",true));
                    fout.append("[SERVER ACTION] -> Using the session key 'K' " + sessionKey +
                        " to compute the secret keys needed for the encryption and hash " +
                        " algorithm.\n");
                    fout.close();
                }
                // calculate the hash for the message.
                String hashHandshakeMsg = CryptoSuite.getRC4Cipher(initialReply);
                String str  = sessionId +" "+  hashHandshakeMsg  + " " + serverRandno +" "+ option;
                retValue = CryptoSuite.writeSocket(clientSocket, str, CryptoSuite.cryptoType.NONE );
                synchronized(fout) {
                    fout=new BufferedWriter(new FileWriter("Server.txt",true));
                    fout.append(SERVER_MSG + "[Session-ID, Keyed hash of message," +
                        " cipher, R{Bob}]-> " + str + "\n");
                    fout.close();
                }
                String hashMsg = CryptoSuite.readFromSocket(clientSocket, CryptoSuite.cryptoType.NONE);
                synchronized(fout) {
                    fout=new BufferedWriter(new FileWriter("Server.txt",true));
                    fout.append(SERVER_MSG + "Keyed hash of message ->" + str + "\n");
                    fout.close();
                }
            }        
            return retValue;
        } catch (Exception e) {
            e.printStackTrace();
        }
        // Return err
        return false;
    }
    
    /**
     * This function is used to handle the key exchange from the client. The message is of the
     * form: P[S]{SECRET} hash(handshakeMsg)
     * Returns success/failure.
     */
    public static boolean respondClientKeyExchange() {
        try {
            String clientKeyMsg = CryptoSuite.readFromSocket(
                    clientSocket, CryptoSuite.cryptoType.NONE);
            // Split the message to get the shared secret and the hashed
            // handshake message.
            synchronized(fout) {
                fout=new BufferedWriter(new FileWriter("Server.txt",true));
                fout.append(CLIENT_MSG + "P{Bob}[S], K(keyed hash of messages)-> " +
                    clientKeyMsg + "\n");
                fout.close();
            }
            String[] handshakeMsgSubstr = clientKeyMsg.split(" ");
            // The first part of the message is the secret key encrypted
            // with Server's public key.
            if (DEBUG)
                System.out.println("client key msg:" + clientKeyMsg);
            byte[] decSecretKey = CryptoSuite.decodeRSACipher(
                    handshakeMsgSubstr[0].getBytes(), CryptoSuite.D, CryptoSuite.N);
            
            // Needed to combine them into bytes.
            sharedSecret = Integer.parseInt(new String(decSecretKey));
            synchronized(fout) {
                fout=new BufferedWriter(new FileWriter("Server.txt",true));
                fout.append("[SERVER ACTION] -> " + "Storing the secret:" + sharedSecret);
                fout.close();
            }
            // Compute the session key K.
            sessionKey = CryptoSuite.calculateKey(sharedSecret, clientRandno, serverRandno);
            synchronized(fout) {
                fout=new BufferedWriter(new FileWriter("Server.txt",true));
                fout.append("[SERVER ACTION] -> " + "Calculating the session key K:" + 
                        sessionKey + " using secret " + sharedSecret +
                        " client random number " + clientRandno + " server random number " +
                        serverRandno + "\n");
                fout.close();
            }
            // Use the session key to generate the secret key and MAC.
            CryptoSuite.initDESKeys(sessionKey);
            synchronized(fout) {
                fout=new BufferedWriter(new FileWriter("Server.txt",true));
                fout.append("[SERVER ACTION] -> Using the session key 'K' " + sessionKey +
                    " to compute the secret keys needed for the encryption and hash " +
                    " algorithm.\n");
                fout.close();
            }
            
            if (DEBUG)
                System.out.println("decrypted shared secret:" + sharedSecret);
            // Send the keyed hash info back to the client.
            boolean retVal = CryptoSuite.writeSocket(clientSocket,
                    handshakeMsgSubstr[1],
                    CryptoSuite.cryptoType.NONE);
            synchronized (fout) {
                fout=new BufferedWriter(new FileWriter("Server.txt",true));
                fout.append(SERVER_MSG + "k(keyed hash of messages)-> " + handshakeMsgSubstr[1] + "\n");
                fout.close();
            }
            return (retVal);
        } catch (Exception e) {
            e.printStackTrace();
        }
        // Return failure.
        return false;
    }
    
    
    public static void main(String[] args) {
        try{
        //INITIALIZATIONS GO HERE..
        sessionId=0;
        DEBUG=true;
        newConnections=true;
        serverPort=9876;
        serverSocket=new ServerSocket(serverPort);
        MAX_CLIENTS=10;
        clientCount=0;
        fout=new BufferedWriter(new FileWriter("Server.txt",true));
        fout.append("SERVER LOG\n");
        fout.append("HOSTNAME: "+InetAddress.getLocalHost().getHostName()+" PORT: "+serverPort+"\n");
        fout.close();
        // Get the configuration info..
        boolean retVal = Util.readConfigurationFile();
        if (!retVal) {
            // close the serverSocket.
            serverSocket.close();
            System.err.println("Failed to read the configuration file.");
            // Return failure.
            System.exit(-1);
        }
        
        // Call the MTM program if Man in the middle needs to be implemented.
        if (Util.isMTMEnabled) {
            String path = System.getProperty("user.dir");
            String cmdName = "java Mim";
            Runtime.getRuntime().exec("ssh " +
                    Util.mtmHost + " cd " + path + "; " +
                    cmdName);            
        }
        System.out.println("************** Secure chat: SERVER SIDE.********************");
        System.out.println("***** 3DES/CBC, 3DES/PCBC, DES/CFB - Privacy protection*****");
        System.out.println("*******************RC4- Integrity protection.****************");
        System.out.println("**** Enter 'quit' to exit from the program. *****************");
        while (newConnections){
            clientCount++;
            sessionId++;
            if (DEBUG){ System.out.println("Ready to accept new client.."); }
            clientSocket=serverSocket.accept();            
            //Start service thread
            serviceThread=new MyThread("service", clientSocket,fout,"Server",null);
            serviceThread.start();
            System.out.println("Reached here..");
            serviceThread.join();
        }
        
        } catch(Exception e) {
            e.printStackTrace();
        }
    }
}