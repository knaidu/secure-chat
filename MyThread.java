import java.net.Socket;
import java.io.*;
import java.util.concurrent.TimeUnit;

public class MyThread extends Thread{
    public int id;
    public Socket sock;
    public Socket serverS;
    public String type;        
    public MyThread reader;
    public MyThread writer;
    public Boolean DEBUG;
    public String reply;
    public static BufferedReader in;
    public static BufferedReader br;
    public static String inputLine;
    public static PrintWriter out;
    public static Boolean alive;
    public static BufferedWriter fout;
    public static String who;
    
    public static final int MAX_TIMEOUT = 5000;
    
    /** Creates a new instance of MyThread */
    public MyThread(String type,Socket sock,BufferedWriter fout,String who, Socket s) {
        this.id=id;
        this.serverS=s;
        this.who=who;
        this.sock=sock;
        this.type=type;
        DEBUG=true;
        reply="";
        alive=true;
        this.fout=fout;
    }
    public void run(){
    try{
        if(type.equalsIgnoreCase("service")){
            if(DEBUG) System.out.println("Service Thread started for client "+id);
            if(DEBUG) System.out.println("Now creating a read thread "+id);
            
            // Protocol specification
            if(who.equalsIgnoreCase("server")){
                boolean retVal = Server.serverHello();
            if (!retVal) {
                fout=new BufferedWriter(new FileWriter(who+".txt",true));
                fout.append("Server: Error in handshake protocol.\n");
                fout.close();
                return;
            }
                
            /*retVal = Server.respondClientKeyExchange();
            if (!retVal) {
                fout=new BufferedWriter(new FileWriter(who+".txt",true));
                fout.append("Server: Error in client key exchange .\n");
                fout.close();
                return;
            }*/
            //CryptoSuite.initDESKeys();       
        }
            // Call the MTM program if Man in the middle needs to be implemented.
            /*if (Util.isMTMEnabled) {
                String path = System.getProperty("user.dir");
                String cmdName = "java Mim";
                Runtime.getRuntime().exec("ssh " +
                        Util.mtmHost + " cd " + path + "; " +
                        cmdName);            
            }*/
            reader=new MyThread("reader", sock,fout,who,serverS);
            reader.start();
            if(DEBUG) System.out.println("Now creating a write thread "+ id);
            writer=new MyThread("writer", sock,fout,who,serverS);
            writer.start();
            reader.join();
            writer.join();
        }
        if(type.equalsIgnoreCase("reader")){
            // step 1. accept input from keyboard
            // step 2. display input on screen
            // step 3. send input to server
            if(who.equalsIgnoreCase("MIM")){
                //step 1. accept input from sand
                //step 2. display input on screen
                //step 3. send input to client
                while(alive){                    
                    String reply = CryptoSuite.readFromSocket(serverS, CryptoSuite.CRYPTO_SUITE.NONE);
                    // This happens when the request timeout or error in readFromSocket.
                    if (reply.compareToIgnoreCase(CryptoSuite.END_BLK) == 0)
                        continue;
                    if((reply == null) ||(reply.compareToIgnoreCase("quit")) == 0) {
                        alive=false;
                        if(who.equalsIgnoreCase("MIM")) Server.newConnections=false;
                        System.out.println("Connection terminated");
                        return;
                    }
                    System.out.println(sock.getInetAddress().getHostName()+" : "+reply);
                    synchronized(fout){
                        fout=new BufferedWriter(new FileWriter(who+".txt",true));
                        fout.append("MSG RECV: "+reply+" \n");
                        fout.close();
                    }
                    System.out.println("MSG RECEIVED FROM SERVER AND SENT: "+reply);
                    synchronized(fout){
                        fout=new BufferedWriter(new FileWriter(who+".txt",true));
                        fout.append("MSG SENT: "+inputLine+" \n");
                        fout.close();
                    }
                    //boolean retVal = CryptoSuite.writeSocket(
                    //        sock,
                            //new String(CryptoSuite.mtmChangeCipherBlock(reply.getBytes())),
                            //CryptoSuite.cryptoType.NONE);                    
                    boolean retVal = CryptoSuite.writeSocket(sock,reply, CryptoSuite.cryptoType.NONE);
                }
            }
                while(alive){
                    ConsoleInput con = new ConsoleInput(5, 5, TimeUnit.SECONDS);
                    String inputLine = con.readLine();
                    //System.out.println("me : "+inputLine);
                    if (inputLine == null) {
                        alive = false;
                        return;
                    }
                    if(inputLine.compareToIgnoreCase("quit") == 0) {
                        System.out.println("quit received..");
                        alive=false;
                        if(who.equalsIgnoreCase("Server")) Server.newConnections=false;
                        boolean retVal;
                        if(who.equalsIgnoreCase("server"))
                                retVal = CryptoSuite.writeSocket(
                                sock,inputLine, Server.crypto);
                        else retVal = CryptoSuite.writeSocket(
                                sock,inputLine, Client.crypto);
                        return;
                    }
                    synchronized(fout){
                        fout=new BufferedWriter(new FileWriter(who+".txt",true));
                        fout.append("MSG SENT: "+inputLine+" \n");
                        fout.close();
                    }
                    boolean retVal;
                    if(who.equalsIgnoreCase("server"))
                    retVal = CryptoSuite.writeSocket(sock,inputLine, Server.crypto);
                    else 
                        retVal = CryptoSuite.writeSocket(sock,inputLine, Client.crypto);
                }
        }
        if(type.equalsIgnoreCase("writer")){
                //setp 1. receive msg
                //step 2. display on screen
            if(who.equalsIgnoreCase("MIM")){
                //step 1. accept input from client
                //step 2. display on screen
                //step 3. send input to server
                while(alive){                    
                    String reply = CryptoSuite.readFromSocket(sock, CryptoSuite.CRYPTO_SUITE.NONE);
                    // This happens when the request timeout or error in readFromSocket.
                    if (reply.compareToIgnoreCase(CryptoSuite.END_BLK) == 0)
                        continue;
                    if((reply == null) ||(reply.compareToIgnoreCase("quit")) == 0) {
                        alive=false;
                        if(who.equalsIgnoreCase("MIM")) Server.newConnections=false;
                        System.out.println("Connection terminated");
                        return;
                    }
                    System.out.println("MSG RECEIVED AND SENT : "+reply);
                    synchronized(fout){
                        fout=new BufferedWriter(new FileWriter(who+".txt",true));
                        fout.append("MSG RECV: "+reply+" \n");
                        fout.close();
                    }
                    boolean retVal = CryptoSuite.writeSocket(serverS,reply, CryptoSuite.CRYPTO_SUITE.NONE);
                }
            }
                while(alive){                    
                    String reply;
                    if(who.equalsIgnoreCase("server"))
                        reply = CryptoSuite.readFromSocket(sock, Server.crypto);
                    else reply = CryptoSuite.readFromSocket(sock, Client.crypto);
                    // This happens when the request timeout in readFromSocket.
                    if (reply.compareToIgnoreCase(CryptoSuite.END_BLK) == 0)
                        continue;
                    if((reply == null) ||(reply.compareToIgnoreCase("quit")) == 0) {
                        alive=false;
                        //if(who.equalsIgnoreCase("Server")) Server.newConnections=false;
                        System.out.println("Connection terminated");
                        return;
                    }
                    System.out.println(sock.getInetAddress().getHostName()+"$$$: "+reply);
                    synchronized(fout){
                        fout=new BufferedWriter(new FileWriter(who+".txt",true));
                        fout.append("MSG RECV: "+reply+" \n");
                        fout.close();
                    }
                }
        }
    }catch(Exception e){e.printStackTrace();}
  }
}