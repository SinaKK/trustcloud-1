
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.MessageDigest;
import java.util.*;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;


public class Server {
    
    private SSLServerSocketFactory sslServerSocket;
    private SSLServerSocket serverConnection;
    private Map<File, ArrayList<String>> files;
    private List<Certificate> certs;
    
    public Server(int port, String keyStore, String password) throws Exception {
        sslServerSocket = (SSLServerSocketFactory) SSLUtilities.getSSLServerSocketFactory(keyStore, password);
        serverConnection = (SSLServerSocket) sslServerSocket.createServerSocket(port, 0,
                InetAddress.getLocalHost());
        System.out.println("Starting on : " + InetAddress.getLocalHost());
        files = new HashMap<File, ArrayList<String>>();
        certs = new ArrayList<Certificate>();
    }
    
    private void receiveFile(SSLSocket connection) throws Exception {
        
        DataInputStream dis = new DataInputStream(connection.getInputStream());
        DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
        
        String filename = dis.readUTF();    // read file name
        
        System.out.println("\tReady to receive file \"" + filename + "\".");
        FileOutputStream fos = new FileOutputStream("./server/"+filename);
        SSLUtilities.readFile(connection, fos);     // read the file
        File f = new File("./server/"+filename);    // create file in the list
       	files.put(f, new ArrayList<String>());
        System.out.println("\tSuccessfully receive file \"" + filename + "\".");
        
        dos.writeBoolean(true);     // tell client upload success
        
        dos.close();
        dis.close();
        fos.close();
    }
    
    private void receiveCert(SSLSocket connection) throws Exception {
    	DataInputStream dis = new DataInputStream(connection.getInputStream());
        DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
        String filename = dis.readUTF();    // read file name
        System.out.println("\tReady to receive certificate \"" + filename + "\".");
        FileOutputStream fos = new FileOutputStream("./server/certs/"+filename);
        SSLUtilities.readFile(connection, fos);     // read the file
        
        File f = new File ("./server/certs/"+filename);
    	CertificateFactory cf = CertificateFactory.getInstance("X.509");
    	BufferedInputStream in = new BufferedInputStream(new FileInputStream(f));
    	Certificate cert = cf.generateCertificate(in);
    	in.close();
    	certs.add(cert);
    	System.out.println("\tSuccessfully receive certificate \"" + filename + "\".");
    	
//    	System.out.println("\n");
//    	System.out.println(cert.toString());
//    	System.out.println("\n");
    	
    	dos.writeBoolean(true);     // tell client upload success
        
        dos.close();
        dis.close();
        fos.close();
    }
    
    private void vouch(SSLSocket connection) throws Exception {

        DataInputStream dis = new DataInputStream(connection.getInputStream());
        DataOutputStream dos = new DataOutputStream(connection.getOutputStream());

        String filename = dis.readUTF();
        String certificate = dis.readUTF();

        // Check if file and certificate are on the server

            // If both are found then 
            try {
                // Hash the file using SHA1.
                String hash = ChecksumSHA1.getSHA1Checksum(filename);

                // Send it to the client for it to encrypt the hash using the client's private key.
                dos.writeUTF(hash);

                // Receive the digital signature from the client and store this information along with the relation to the indicated certificate.
            }     
            catch (Exception e) {
                e.printStackTrace();
            }

    	/* test code
    	Certificate c1 = certs.get(0);
    	System.out.println(c1.toString());
        Certificate c2 = certs.get(1);
    	System.out.println(c2.toString());
        
    	try {
			c2.verify(c1.getPublicKey());
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        */
    	System.out.println("ok");

    }
     
    private void sendFile(SSLSocket connection) throws Exception {
        DataInputStream dis = new DataInputStream(connection.getInputStream());
        DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
        String filename = dis.readUTF();
        File requested = new File("./server/"+filename);
        if (files.containsKey(requested)) {
            System.out.println("\tReady to send file \"" + filename + "\".");
            dos.writeBoolean(true);     // tell client server has the file and ready to send
            SSLUtilities.writeFile(connection, requested);
            System.out.println("\tSuccessfully send file \"" + filename + "\".");
        } else {
            dos.writeBoolean(false);    // tell client server does not have the file
            System.out.println("\tError: \"" + filename + "\" does not exist.");
        }
        dis.close();
        dos.close();
    }
    
    private void listProtection(SSLSocket connection) {
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
            } else if (cmd.equalsIgnoreCase("UPLOAD_CERT")) {
            	receiveCert(connection);
            } else if (cmd.equalsIgnoreCase("VOUCH")) {
                vouch(connection);
            } else {
            	dis.close();
            	connection.close();
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
