import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;


public class Client {
	private SSLSocketFactory sslSocket;
	
    public Client(String trustFile, String password) throws Exception {
    	//System.out.println("Client created at " + InetAddress.getLocalHost().getCanonicalHostName());
        
        sslSocket = (SSLSocketFactory) SSLUtilities.getSSLSocketFactory(trustFile, password);
    }
    
    
    public void requestToAdd(String path) throws Exception {
    	SSLSocket connection = (SSLSocket) sslSocket.createSocket("192.168.1.101", 8000);
    	//DataInputStream dis = new DataInputStream(connection.getInputStream());
    	DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
    	File f = new File(path);
    	dos.writeUTF("ADD");
    	dos.writeUTF(f.getName());
    	SSLUtilities.writeFile(connection, f);	
    	
    	dos.close();
    	connection.close();
    }
    
    public static void main(String[] args) throws Exception {
		if (args.length != 3) {
            System.err.println("Usage: java Client truststore_filepath truststore_password path");
            System.exit(1);
        }
		String truststore = args[0];
        String password = args[1];
        String path = args[2];
        Client c = new Client(truststore, password);
        
        c.requestToAdd(path);
        
	}
    
}

