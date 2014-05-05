
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.net.InetAddress;
import java.util.*;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;


public class Server {
	
	private SSLServerSocketFactory sslServerSocket;
	private SSLServerSocket serverConnection;
	private List<File> files;
	
    public Server(int port, String keyStore, String password) throws Exception {
        sslServerSocket = (SSLServerSocketFactory) SSLUtilities.getSSLServerSocketFactory(keyStore, password);
        serverConnection = (SSLServerSocket) sslServerSocket.createServerSocket(port, 0,
                InetAddress.getLocalHost());
        System.out.println("Starting on : " + InetAddress.getLocalHost());
        files = new ArrayList<File>();
    }    

    private void receiveFile(SSLSocket connection) throws Exception {
    	
    	DataInputStream dis = new DataInputStream(connection.getInputStream());
    	DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
    	
    	String filename = dis.readUTF();	// read file name
    	
    	System.out.println("\tReady to receive file \"" + filename + "\".");
    	FileOutputStream fos = new FileOutputStream("./server/"+filename);
		SSLUtilities.readFile(connection, fos); 	// read the file
    	
    	File f = new File("./server/"+filename); 	// store the file in the list
    	files.add(f);
    	System.out.println("\tSuccessfully receive file \"" + filename + "\".");
    	
    	dos.writeBoolean(true); 	// tell client file upload success
    	
    	dos.close();
    	dis.close();
    	fos.close();
    }
    
    private void sendFile(SSLSocket connection) throws Exception {
    	DataInputStream dis = new DataInputStream(connection.getInputStream());
    	DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
    	String filename = dis.readUTF();
    	File requested = new File("./server/"+filename);
    	if (files.contains(requested)) {
    		System.out.println("\tReady to send file \"" + filename + "\".");
    		dos.writeBoolean(true);		// tell client server has the file and ready to send
    		SSLUtilities.writeFile(connection, requested);
    		System.out.println("\tSuccessfully send file \"" + filename + "\".");
    	} else {
    		dos.writeBoolean(false); 	// tell client server does not have the file
    		System.out.println("\tError: \"" + filename + "\" does not exist.");
    	}
    	dis.close();
    	dos.close();
    }
    
    private void listProtection(SSLSocket connection) {
    	return;
    }
    
    private void vouch(SSLSocket connection) {
    	return;
    }
    
    private void listen() throws Exception {
    	
        System.out.println("Listening......");
        while (true) {
            SSLSocket connection = (SSLSocket) serverConnection.accept();  
            DataInputStream dis = new DataInputStream(connection.getInputStream());
           	String cmd = dis.readUTF();
            if (cmd.equalsIgnoreCase("UPLOAD")) {
                receiveFile(connection);
            } else if (cmd.equalsIgnoreCase("FETCH")) {
                sendFile(connection);
            } else if (cmd.equalsIgnoreCase("LIST")) {
            	listProtection(connection);
            	break;
            } else if (cmd.equalsIgnoreCase("VOUCH")) {
            	vouch(connection);
            	break;
            } else {
            	break;
            }
            dis.close();
            connection.close();
        }
    }
    
	public static void main(String[] args) throws Exception {
		if (args.length != 3) {
            System.err.println("Usage: java Server port keystore_filepath keystore_password");
            System.exit(1);
        }
		
		int port = Integer.parseInt(args[0]);
		String keyStore = args[1];
		String password = args[2];
		
		Server s = new Server(port, keyStore, password);
		s.listen();

	}
}
