/**
 * @file ConsoleInputReadTask.java This file contains code to read console input for secure chat application
 * @author Karthik Naidu
 */
import java.io.*;
import java.util.concurrent.Callable;

public class ConsoleInputReadTask implements Callable<String> {
  public String call() throws IOException {
    BufferedReader br = new BufferedReader(
        new InputStreamReader(System.in));
    
    String input;
    do {      
      try {
          // wait until we have data to complete a readLine()
        	while (!br.ready()) {
       			Thread.sleep(200);
         	}
         	input = br.readLine();
         } catch (InterruptedException e) {       		
                return null;
         }
      } while ("".equals(input));      
      return input;
    }
 }
                                                                        
