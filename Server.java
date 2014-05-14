import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.*;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;


public class Server {
    
	public static final String ROOTFOLDER = "./trustcloud/";
	
    private SSLServerSocketFactory sslServerSocket;
    private SSLServerSocket serverConnection;
    private Map<String, ArrayList<String>> files; // Map files to signatures
    private Map<String, Certificate> signatureCerts; // Map signatures to certificates
    private List<Certificate> certs;
    
    public Server(int port, String keyStore, String password) throws Exception {
        sslServerSocket = (SSLServerSocketFactory) SSLUtilities.getSSLServerSocketFactory(keyStore, password);
        serverConnection = (SSLServerSocket) sslServerSocket.createServerSocket(port, 0,
                InetAddress.getLocalHost());
        System.out.println("Starting on : " + InetAddress.getLocalHost());
    }
    
    @SuppressWarnings("unchecked")
	private void loadStates() throws Exception {
    	
    	/* loading server stored certificates information */
    	File f = new File(ROOTFOLDER+"certs.state");
    	if (f.isFile()) {
    		System.out.println("Start loading certificates...");
    		FileInputStream fis = new FileInputStream(f);
    		ObjectInputStream ois = new ObjectInputStream(fis);
    		this.certs = (ArrayList<Certificate>) ois.readObject();
    		ois.close();
    		fis.close();
    		System.out.println("Certificates Loading done.");
    	} else {
    		this.certs = new ArrayList<Certificate>();
    	}
    	
    	/* loading server stored files and its signature information */
    	f = new File(ROOTFOLDER+"files.state");
    	if (f.isFile()) {
    		System.out.println("Start loading files...");
    		FileInputStream fis = new FileInputStream(f);
    		ObjectInputStream ois = new ObjectInputStream(fis);
    		this.files = (HashMap<String, ArrayList<String>>) ois.readObject();
    		ois.close();
    		fis.close();
    		System.out.println("Files loading done.");
    	} else {
    		this.files = new HashMap<String, ArrayList<String>>();
    	}
    	
    	signatureCerts = new HashMap<String, Certificate>();
    }
    
    
    private void saveCerts() throws Exception {
    	File f = new File(ROOTFOLDER+"certs.state");
    	FileOutputStream fos = new FileOutputStream(f);
    	ObjectOutputStream oos = new ObjectOutputStream(fos);
    	System.out.println("\tStart saving...");
    	oos.writeObject(this.certs);
    	oos.close();
    	System.out.println("\tSaving done.");
    }
    
    
    private void receiveFile(SSLSocket connection) throws Exception {
        
        DataInputStream dis = new DataInputStream(connection.getInputStream());
        DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
        
        String filename = dis.readUTF();    // read file name
        
        System.out.println("\tReady to receive file \"" + filename + "\".");
        FileOutputStream fos = new FileOutputStream(ROOTFOLDER+filename);
        SSLUtilities.readFile(connection, fos);     // read the file
       	files.put(filename, new ArrayList<String>());
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
        FileOutputStream fos = new FileOutputStream(ROOTFOLDER+"/certs/"+filename);
        SSLUtilities.readFile(connection, fos);     // read the file
        
        File f = new File (ROOTFOLDER+"/certs/"+filename);
    	CertificateFactory cf = CertificateFactory.getInstance("X.509");
    	BufferedInputStream in = new BufferedInputStream(new FileInputStream(f));
    	Certificate cert = cf.generateCertificate(in);
    	in.close();
    	certs.add(cert);
    	System.out.println("\tSuccessfully receive certificate \"" + filename + "\".");
    	
    	dos.writeBoolean(true);     // tell client upload success
        
        dos.close();
        dis.close();
        fos.close();
        saveCerts();
    }
    
    private void vouch(SSLSocket connection) throws Exception {

        DataInputStream dis = new DataInputStream(connection.getInputStream());
        DataOutputStream dos = new DataOutputStream(connection.getOutputStream());

        String filename = dis.readUTF();
        String certificate = dis.readUTF();

        // Check if file and certificate are on the server
        File fFile = new File(ROOTFOLDER+filename);
        File fCertificate = new File(ROOTFOLDER+certificate);
        
        if (fFile.isFile() && fCertificate.isFile()) {
            // If both are found then 
            try {
                // Hash the file using SHA1.
                String hash = ChecksumSHA1.getSHA1Checksum(filename);

                // Send it to the client for it to encrypt the hash using the client's private key.
                dos.writeUTF(hash);

                // Receive the digital signature from the client
                String digSig = dis.readUTF();

                // Store relation between file and signatures
                files.get(filename).add(digSig);

                // Store signature relation to certificate
                File f = new File (ROOTFOLDER+certificate);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                BufferedInputStream in = new BufferedInputStream(new FileInputStream(f));
                Certificate cert = cf.generateCertificate(in);
                in.close();

                signatureCerts.put(digSig, cert);
            }     
            catch (Exception e) {
                e.printStackTrace();
            }
        }
        else {
            System.out.println("No file or certificate found.");
        }
    }
    
    
    /**
     * Return if c2 is the issuer of c1
     * @param c1 the subject
     * @param c2 the issuer
     * @return
     */
    private boolean isIssuer (Certificate c1, Certificate c2) {
    	boolean isIssuer = true;
    	try {
			c2.verify(c1.getPublicKey());
		} catch (InvalidKeyException e) {
			isIssuer = false;
			e.printStackTrace();
		} catch (CertificateException e) {
			isIssuer = false;
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			isIssuer = false;
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			isIssuer = false;
			e.printStackTrace();
		} catch (SignatureException e) {
			isIssuer = false;
			e.printStackTrace();
		}
    	return isIssuer;
    }
    
    
    /**
     * Check the ring of trust where Certificate c is in
     * @param c Certificate
     * @return the size of the ring where Certificate c is in
     * 			0 as c is not in any ring	
     */
    private int ringSize(Certificate c) {
    	// TODO
    	return 0;
    }
    
    
    private boolean isSafe (File f, int circumference) {
    	
    	if (circumference == -1) return true;
//    	ArrayList<String> sigs = this.files.get(ROOTFOLDER + f.getName());
//    	
//    	for (String sig : sigs) { // iterate through each signature of the file
//    		if (ringSize(signatureCerts.get(sig)) >= circumference) {
//    			return true;
//    		}
//    	}
    	
    	return true;
    }
    
    
    /**
     * Send file to the client
     * @param connection
     * @throws Exception
     */
    private void sendFile(SSLSocket connection) throws Exception {
        DataInputStream dis = new DataInputStream(connection.getInputStream());
        DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
        
        String filename = dis.readUTF();
        int circumference = dis.readInt();
        
        File requested = new File(ROOTFOLDER+filename);
        if (files.containsKey(filename) && requested.isFile()) {
        	System.out.println("\tReady to send file \"" + filename + "\".");
        	if (isSafe(requested, circumference)) {
        		dos.writeInt(1);     // tell client that server has the file and ready to send
                SSLUtilities.writeFile(connection, requested);
                System.out.println("\tSuccessfully send file \"" + filename + "\".");
        	} else {
        		dos.writeInt(-1);	// tell client that the file on the server is not safe enough
        		System.out.println("\tAbort file transfer due to insufficient security");
        	}
        } else {
            dos.writeInt(0);    // tell client that server does not have the file
            System.out.println("\tError: \"" + filename + "\" does not exist.");
        }
        
        dis.close();
        dos.close();
    }
    
    
    /**
     * List out all the stored data files and how they are protected to the client
     * @param connection
     * @throws Exception
     */
    private void listProtection(SSLSocket connection) throws Exception {
    	DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
        
        
        dos.close();
    }
    
    
    /**
     * Listen for clients' connection requests
     * @throws Exception
     */
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
        s.loadStates();
        s.listen();
    }
}
