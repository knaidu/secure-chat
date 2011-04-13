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
public class Mim {
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
    public static BufferedWriter fout;
    public static String serverName;
    public static Socket s;
    public static MyThread reader,writer;
    public static String initialString,serverReply;
    
    
    public static int getRandomNumber(){
        Random rand=new Random();
        return rand.nextInt(1234567);
    }
    public static void serverHello(){
        initialReply = CryptoSuite.readFromSocket(clientSocket, CryptoSuite.cryptoType.NONE);
        if(DEBUG) System.out.println("Initial reply: "+initialReply);
        String str  = sessionId+" "+"CERTIFICATE"+" "+getRandomNumber()+" "+"CHOSEN-CIPHER";
        boolean retValue = CryptoSuite.writeSocket(clientSocket, str, CryptoSuite.cryptoType.NONE );
    }
    public static void clientHello(){
        //sends a hello msg to server, msg includes random number + list of ciphers supported
        initialString=getRandomNumber()+" Cipher1 Cipher2 Cipher3";
        boolean retValue = CryptoSuite.writeSocket(s,initialString,
                    CryptoSuite.cryptoType.NONE);
    }
    public static void main(String[] args) {
        try{
        //INITIALIZATIONS GO HERE..
        sessionId=0;
        DEBUG=true;
        newConnections=true;
        //Connect to server.. (Acting as client)
        boolean retVal = Util.readConfigurationFile();
        //serverName="sand.cise.ufl.edu";
        serverName = Util.serverName;
            
        serverPort=9876;
        fout=new BufferedWriter(new FileWriter("Mim.txt",true));
        //initialString=getRandomNumber()+" Cipher1 Cipher2 Cipher3";

        s=new Socket(serverName,serverPort);

        fout.append("MAN IN THE MIDDLE LOG\n");
        fout.append("MTM HOSTNAME: "+InetAddress.getLocalHost().getHostName()+" ");

        //reader=new MyThread("reader",s,fout,"Client");
        //writer=new MyThread("writer",s,fout,"Client");
        //Session initiatiation
        //Send R-server and ciphers
        //PROTOCOL
        clientHello();
        serverReply = CryptoSuite.readFromSocket(s, CryptoSuite.cryptoType.NONE);            
        System.out.println("Initial Server reply: "+serverReply);
        fout.append("CLIENT ID: "+serverReply.substring(0,1)+"\n");

        //Then start reader and writer threads
        fout.close();
        CryptoSuite.initDESKeys("1234567890");
        //reader.start();
        //writer.start();
        //reader.join();
        //writer.join();
        //s.close();            
        
        //Open connection for client to connect (Acting as server)
        serverPort=9876;
        serverSocket=new ServerSocket(serverPort);
        MAX_CLIENTS=10;
        clientCount=0;
        while (newConnections){
            clientCount++;
            sessionId++;
            if (DEBUG){ System.out.println("Ready to accept new client.."); }
            clientSocket=serverSocket.accept();
            //PROTOCOL
            serverHello();
            CryptoSuite.initDESKeys("1234567890");
            
            //Start service thread
            serviceThread=new MyThread("service", clientSocket,fout,"MIM",s);
            serviceThread.start();
        }
        
        }catch(Exception e){ e.printStackTrace();}
    }
}