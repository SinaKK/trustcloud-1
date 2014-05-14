import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Queue;
import java.util.Set;
import java.util.TreeSet;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;


public class Server {
    
	public static final String ROOTFOLDER = "./trustcloud/";
	public static final String CERTFOLDER = ROOTFOLDER + "/certs/";
	
    private SSLServerSocketFactory sslServerSocket;
    private SSLServerSocket serverConnection;
    private HashMap<String, ArrayList<String>> files; // Map files to signatures
    private HashMap<String, String> signatureCerts; // Map signatures to its owner
    private HashMap<String, ArrayList<X509Certificate>> issuerCerts;
    private HashMap<String, ArrayList<X509Certificate>> subjectCerts;
    private HashMap<String, TreeSet<String>> subject_issuer;
    
    /**
     * TrustCloud initialize with a keystore file and its password and a port number.
     * @param port port number where the server starts
     * @param keyStore keystore file where the private key of server is stored
     * @param password password of the keystore file
     * @throws Exception
     */
    public Server(int port, String keyStore, String password) throws Exception {
        sslServerSocket = (SSLServerSocketFactory) SSLUtilities.getSSLServerSocketFactory(keyStore, password);
        serverConnection = (SSLServerSocket) sslServerSocket.createServerSocket(port, 0,
                InetAddress.getLocalHost());
        System.out.println("Starting on: " + InetAddress.getLocalHost().getHostAddress());
    }
    
    
    /**
     * Loading the TrustCloud server states, including its files and their signatures and certificates
     * @throws Exception
     */
    @SuppressWarnings("unchecked")
	private void loadStates() throws Exception {
    	
    	/* create certificate folder */
    	File certDir = new File(CERTFOLDER);
		if (!certDir.isDirectory()) {
			certDir.mkdir();
		}  
    	
    	/* loading server stored certificates information */
    	File f = new File(ROOTFOLDER+"certs.state");
    	if (f.isFile()) {
    		System.out.println("Loading certificates...");
    		FileInputStream fis = new FileInputStream(f);
    		ObjectInputStream ois = new ObjectInputStream(fis);
    		this.subjectCerts  = (HashMap<String, ArrayList<X509Certificate>>) ois.readObject();
    		this.issuerCerts = (HashMap<String, ArrayList<X509Certificate>>) ois.readObject();
    		this.subject_issuer = (HashMap<String, TreeSet<String>>) ois.readObject();
    		ois.close();
    		fis.close();
    		System.out.println("Certificates Loading done.");
    	} else {
    		issuerCerts = new HashMap<String, ArrayList<X509Certificate>>();
        	subjectCerts = new HashMap<String, ArrayList<X509Certificate>>();
        	subject_issuer = new HashMap<String, TreeSet<String>>();
    	}
    	
    	/* loading server stored files and its signature information */
    	f = new File(ROOTFOLDER+"files.state");
    	if (f.isFile()) {
    		System.out.println("Loading files...");
    		FileInputStream fis = new FileInputStream(f);
    		ObjectInputStream ois = new ObjectInputStream(fis);
    		this.files = (HashMap<String, ArrayList<String>>) ois.readObject();
    		ois.close();
    		fis.close();
    		System.out.println("Files loading done.");
    	} else {
    		this.files = new HashMap<String, ArrayList<String>>();
    	}
    	
    	/* loading server stored signatures information */
    	f = new File(ROOTFOLDER + "sigs.state");
    	if (f.isFile()) {
    		System.out.println("Loading signatures...");
    		FileInputStream fis = new FileInputStream(f);
    		ObjectInputStream ois = new ObjectInputStream(fis);
    		this.signatureCerts = (HashMap<String, String>)ois.readObject();
    		ois.close();
    		fis.close();
    		System.out.println("Signatures loading done.");
    	} else {
    		signatureCerts = new HashMap<String, String>();
    	}
    }
    
    
    /**
     * Save the states of certificates information
     * @throws Exception
     */
    private void saveCerts() throws Exception {
    	File f = new File(ROOTFOLDER + "certs.state");
    	FileOutputStream fos = new FileOutputStream(f);
    	ObjectOutputStream oos = new ObjectOutputStream(fos);
    	System.out.println("\tSaving certificates...");
    	oos.writeObject(this.subjectCerts);
    	oos.writeObject(this.issuerCerts);
    	oos.writeObject(this.subject_issuer);
    	oos.close();
    	fos.close();
    	System.out.println("\tCertificates saving done.");
    }
    
    
    /**
     * Save the states of signature
     * @throws Exception
     */
    private void saveSignature() throws Exception {
    	File f = new File(ROOTFOLDER + "sigs.state");
    	FileOutputStream fos = new FileOutputStream(f);
    	ObjectOutputStream oos = new ObjectOutputStream(fos);
    	System.out.println("\tSaving signaturess...");
    	oos.writeObject(this.signatureCerts);
    	oos.close();
    	fos.close();
    	System.out.println("\tSignatures saving done.");
    }
    
    
    /**
     * Link to Client.upload
     * Receive a data file from client
     * @param connection the SSL connection
     * @throws Exception
     */
    private void receiveFile(SSLSocket connection) throws Exception {
        DataInputStream dis = new DataInputStream(connection.getInputStream());
        DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
        
        /* read in the name of the file */
        String filename = dis.readUTF();
        
        // TODO when file is already on the server
        
        /* read in the data file store it on the server */
        System.out.println("\tReady to receive file \"" + filename + "\".");
        FileOutputStream fos = new FileOutputStream(ROOTFOLDER + filename);
        SSLUtilities.readFile(connection, fos);
       	
        /* record the file */
        files.put(filename, new ArrayList<String>());
        System.out.println("\tSuccessfully receive file \"" + filename + "\".");
        
        /* send feed back to client */
        dos.writeBoolean(true);
        
        dos.close();
        dis.close();
        fos.close();
    }
    
    
    /**
     * Link to Clien.upload
     * Receive a certificate file from client 
     * @param connection the SSL connection
     * @throws Exception
     */
    private void receiveCert(SSLSocket connection) throws Exception {
    	DataInputStream dis = new DataInputStream(connection.getInputStream());
        DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
        
        /* read in the filename of the certificate */
        String filename = dis.readUTF();
        System.out.println("\tReady to receive certificate \"" + filename + "\".");
        
        /* read in the certificate file and store it on the server */
        FileOutputStream fos = new FileOutputStream(CERTFOLDER + filename);
        SSLUtilities.readFile(connection, fos);
        System.out.println("\tSuccessfully receive certificate \"" + filename + "\".");
        
        /* read in the certificate information from the file */
        File f = new File (CERTFOLDER + filename);
    	CertificateFactory cf = CertificateFactory.getInstance("X.509");
    	BufferedInputStream in = new BufferedInputStream(new FileInputStream(f));
    	X509Certificate cert = (X509Certificate)cf.generateCertificate(in);
    	in.close();
    	
    	/* record the certificate */
    	addNewCert(cert);
    	
    	/* send feedback to client */
    	dos.writeBoolean(true);
        
        /* save the certificate states */
        saveCerts();
        
        dos.close();
        dis.close();
        fos.close();
    }

    
    /**
     * Add the new certificate the both subject and issuer map
     * @param cert certificate to be added
     */
    private void addNewCert(X509Certificate cert) {
    	
    	String subject = cert.getSubjectX500Principal().getName();
    	String issuer = cert.getIssuerX500Principal().getName();
    	
    	/* add the certificate to the person who owns the certificate */
    	if (!subjectCerts.containsKey(subject)) subjectCerts.put(subject, new ArrayList<X509Certificate>());	
    	subjectCerts.get(subject).add(cert);
    	
    	/* add the certificate to the person who signs the certificate */
    	if (!issuerCerts.containsKey(issuer)) issuerCerts.put(issuer, new ArrayList<X509Certificate>());
    	issuerCerts.get(issuer).add(cert);
    	
    	/* add the subject-issuer relation */
    	if (!subject_issuer.containsKey(subject)) subject_issuer.put(subject, new TreeSet<String>());
    	subject_issuer.get(subject).add(issuer);
    }
    
    
    private void vouch(SSLSocket connection) throws Exception {

        DataInputStream dis = new DataInputStream(connection.getInputStream());
        DataOutputStream dos = new DataOutputStream(connection.getOutputStream());

        String filename = dis.readUTF();
        String certificate = dis.readUTF();

        File file = new File(ROOTFOLDER+filename);
        if (file.isFile()) {
        	if (subjectCerts.containsKey(certificate)) {
        		
        		System.out.println("\tReady to vouch for file \"" + filename + 
        				"\" using certificate \"" + certificate + "\".");
        		// Hash the file using SHA1.
                String hash = ChecksumSHA1.getSHA1Checksum(filename);

                // Send it to the client for it to encrypt the hash using the client's private key.
                dos.writeUTF(hash);

                // Receive the digital signature from the client
                String digSig = dis.readUTF();

                // Store relation between file and signatures
                files.get(filename).add(digSig);

                // Store signature relation to certificate
                File f = new File (CERTFOLDER + certificate);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                BufferedInputStream in = new BufferedInputStream(new FileInputStream(f));
                X509Certificate cert = (X509Certificate)cf.generateCertificate(in);
                in.close();
                signatureCerts.put(digSig, cert.getSubjectX500Principal().getName());
                saveSignature();
                
        	} else System.out.println("\tVouching failed: cannot find specified certificate.");
        } else System.out.println("\tVouching failed, cannot find specified file");
     
        dis.close();
        dos.close();
    }
    
    
    private int ringSize(String subject) {
    	// TODO
    	int size = 0;
    	Queue<String> q = new LinkedList<String>();
    	Set<String> gone = new TreeSet<String>();
    	
    	System.out.println("Checking " + subject);
    	
    	for (String issuer : subject_issuer.get(subject)) {
    		System.out.println("adding " + issuer);
    		q.add(issuer);
    	}
    	gone.add(subject);
    	
    	while (true) {
    		String top = q.poll();
    		gone.add(top);
    		/* DEAD END. top's certificate is not in the server*/
    		if (!subject_issuer.containsKey(top)) {
    			continue;
    		}
    		
    		if (top.equals(subject)) {
    			size++;
    			continue;
    		}
    		
    		/* find out who has issued certificate for top */
    		for (String issuer: subject_issuer.get(top)) {
    			if (!q.contains(issuer) && !gone.contains(issuer)) {
    				System.out.println("adding " + issuer);
    				q.add(issuer);
    			}
    			
    		}
    		size++;
    		if (q.isEmpty()) {
    			break;
    		}
    	}
    	
    	return size;
    }
    
    
    private void test(SSLSocket connection) throws Exception {
    	DataInputStream dis = new DataInputStream(connection.getInputStream());
    	File f = new File (CERTFOLDER + "Picu.crt");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        BufferedInputStream in = new BufferedInputStream(new FileInputStream(f));
        X509Certificate cert = (X509Certificate)cf.generateCertificate(in);
        in.close();
    	
        int r = ringSize((cert.getSubjectX500Principal().getName()));
    	
    	System.out.println(r);
    	
    	dis.close();
    }
    
    
    /**
     * Check is a data file has required safety
     * @param f the data file to be checked
     * @param circumference the length of the ring of the trust
     * @return true is the the file is in at least one ring that has the required length
     */
    private boolean isSafe (File f, int circumference) {
    	
    	if (circumference < 2) return true;
    	
    	ArrayList<String> sigs = this.files.get(ROOTFOLDER + f.getName());
    	
    	if (sigs == null) { // when no one has signed the data file
    		return false;
    	}
    	
    	for (String sig : sigs) { // iterate through each signature of the file, and check its corresponding ring
    		if (ringSize(signatureCerts.get(sig)) >= circumference) {
    			return true;
    		}
    	}
    	
    	return false; // none of its ring has the minimum size of the required length
    }
    
    
    /**
     * Send a data file to the client
     * @param connection
     * @throws Exception
     */
    private void sendFile(SSLSocket connection) throws Exception {
        DataInputStream dis = new DataInputStream(connection.getInputStream());
        DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
        
        /* read in the filename of the data file and the required length of ring of trust */
        String filename = dis.readUTF();
        int circumference = dis.readInt();
        
        // TODO better logic, need to check against its signature
        File requested = new File(ROOTFOLDER + filename);
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
        
    	// TODO
        
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
            } else if (cmd.equalsIgnoreCase("TEST")) {
                test(connection);
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
