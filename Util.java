/*
 * Util.java
 *
 * Created on November 27, 2007, 8:18 PM
 *
 * To change this template, choose Tools | Template Manager
 * and open the template in the editor.
 */

/**
 *
 * @author Balaji Subramanian (UFID:9145-9791)
 */
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileNotFoundException;


/**
 * This class is used to perform the utility functions and
 * generating the handshake messages for the client and server.
 */
public class Util {
    
    public static final String INP_FILE = "system.properties";
    public static String serverName;
    public static int serverPort;
    public static String clientName;
    public static int clientPort;
    public static String mtmHost;
    public static boolean isMTMEnabled;
    
    /** Creates a new instance of Util */
    public Util() {
    }
    
    /**
     * This function is used to read the configuration file system.properties and
     * populate the Util class data structure. The configuration file location is
     * known system path.
     */
    public static boolean readConfigurationFile() {
        try {
            String path = System.getProperty("user.dir");
            if (INP_FILE == null) {
                System.err.println("Error: No config file.");
                System.exit(-1);
            }
            BufferedReader br = new BufferedReader (
                new FileReader(path + "/" + INP_FILE));
            String str = null;
            while ((str = br.readLine()) != null) {
                String nameValue[] = str.split("=");
                if (nameValue[0].compareTo("Servername") == 0)
                    serverName = nameValue[1];
                else if (nameValue[0].compareTo("Clientname")== 0)
                    clientName = nameValue[1];
                else if (nameValue[0].compareTo("MTMname")== 0)
                    mtmHost = nameValue[1];
                else if (nameValue[0].compareTo("enableMTM") == 0)
                    isMTMEnabled = nameValue[1].compareToIgnoreCase("true") == 0 ?
                        true : false;
                else
                    continue;                
            }
            // Return Success
            return true;
        } catch (FileNotFoundException fe) {
           System.err.println("File " + INP_FILE + " does not exist");
        } catch (Exception e) {
            e.printStackTrace();
        }
        // Return error.
        return false;
    }
}
