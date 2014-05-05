
import java.io.DataInputStream;
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
    	String filename = dis.readUTF();
    	System.out.println(filename);
    	FileOutputStream fos = new FileOutputStream("./server/"+filename);
		SSLUtilities.readFile(connection, fos);
    	
    	File f = new File("./server/"+filename);
    	files.add(f);
    	System.out.println(files.get(0).getName());
    	dis.close();
    	fos.close();
    }
    
    private void listen() throws Exception {
        System.out.println("Listening......");
        
        while (true) {
            SSLSocket connection = (SSLSocket) serverConnection.accept();   
            DataInputStream dis = new DataInputStream(connection.getInputStream());
            String cmd = dis.readUTF();
            if (cmd.equalsIgnoreCase("ADD")) {
                receiveFile(connection);
            } else if (cmd.equalsIgnoreCase("FECTH")) {

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
