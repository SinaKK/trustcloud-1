import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;


public class Client {
	
	public static final int FILE = 1;
	public static final int CERTIFICATE = 2;
	
    private SSLSocketFactory sslSocket;
    private String hostaddress;
    private int hostport = -1;
    
    
    public Client(String trustFile, String password) throws Exception {
        sslSocket = (SSLSocketFactory) SSLUtilities.getSSLSocketFactory(trustFile, password);
        hostaddress = null;
    }
       
    
    /**
     * Upload a file to trustcloud
     * @param filename the name of the file
     * @param type indicates if the file is a data file or a certificate
     * @throws Exception
     */
    public void upload(String filename, int type) throws Exception {
        SSLSocket connection = (SSLSocket) sslSocket.createSocket(hostaddress, hostport);
        DataInputStream dis = new DataInputStream(connection.getInputStream());
        DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
        File f = new File(filename);
        
        if (type == FILE) { 
        	dos.writeUTF("UPLOAD");
        }
        if (type == CERTIFICATE) {
        	dos.writeUTF("UPLOAD_CERT");
        }
        dos.writeUTF(f.getName());
        SSLUtilities.writeFile(connection, f);
        
        if (dis.readBoolean()) {    // read boolean
        	if (type == FILE) {
            	System.out.println("File \"" + filename + "\" upload success."); 
            } else if (type == CERTIFICATE) {
            	System.out.println("Certificate \"" + filename + "\" upload success."); 
            }
        } else {
            System.out.println("Upload failed.");
        }
        
        dos.close();
        dis.close();
        connection.close();
    }

    
    /**
     * Download a data file from trustcloud, and 
     * the file must be in a ring of trust that has the specified circumference.
     * @param filename the name of the file to be download.
     * @param circumference	the minimum length the ring of trust that the file must be in.
     * @throws Exception
     */
    public void fetch(String filename, int circumference) throws Exception {
        SSLSocket connection = (SSLSocket) sslSocket.createSocket(hostaddress, hostport);
        DataInputStream dis = new DataInputStream(connection.getInputStream());
        DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
        
        dos.writeUTF("FETCH"); 
        dos.writeUTF(filename);     
        dos.writeInt(circumference);
        
        int status = dis.readInt();
        switch (status) {
        case 1:		// trustcloud has the file and it is of the required safety level
        	System.out.println("Reading \"" + filename + "\".........\n(Start of the file)");
            SSLUtilities.readFile(connection, System.out);
            System.out.println("\n(End of the file)");
            break;
        case 0:
        	System.out.println("The trustcloud does not has the file.");
        	break;
        case -1:
        	System.out.println("The file on the trustcloud is not \"safe\" enough.");
        	break;
        }
        
        dis.close();
        dos.close();
        connection.close();
    }
    
    
    /**
     * List all stored data files and how they are protected.
     * @throws IOException
     */
    public void list() throws IOException {
    	SSLSocket connection = (SSLSocket) sslSocket.createSocket(hostaddress, hostport);
        DataInputStream dis = new DataInputStream(connection.getInputStream());
        DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
        
        dos.writeUTF("LIST");
        
        String protections = dis.readUTF();
        
        System.out.println(protections);
        
        dos.close();
        dis.close();
        connection.close();
    }
    
    
    /**
     * 
     * @param filename
     * @param certificate
     * @throws Exception
     */
    public void vouch(String filename, String certificate) throws Exception {
    	SSLSocket connection = (SSLSocket) sslSocket.createSocket(hostaddress, hostport);
        DataInputStream dis = new DataInputStream(connection.getInputStream());
        DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
        dos.writeUTF("VOUCH");      // write command

        dos.writeUTF(filename);
        dos.writeUTF(certificate);

        // Receive hash of the file from the server if the file is found.
        String hash = dis.readUTF();

        // Encrypt the hash with the client's private key.

        // Send the resulting digital signature back to the server.

        dos.close();
        dis.close();
        connection.close();
    }
    
    
    /**
     * Set the host address and port
     * @param hostaddress in the form of 000.000.000.000:0000
     */
    private void setHost(String hostaddress) {
        int seperate = hostaddress.indexOf(":");
        this.hostaddress = hostaddress.substring(0, seperate);
        this.hostport = Integer.parseInt(hostaddress.substring(seperate+1));
    }
    
    
    /**
     * Print out command line options help
     */
    private static void printCommandHelp() {
        System.out.println("\n===================Command line options: (* required)===================");
        System.out.println("-a filename               add or replace a file to the trustcloud");
        System.out.println("-c number                 provide the required circumference of a ring of trust");
        System.out.println("-f filename               fetch an existing file from the trustcloud server");
        System.out.println("-h hostname:port  (*)     provide the remote address hosting the trustcloud server");
        System.out.println("-l                        list all stored files and how they are protected");
        System.out.println("-u certificate            upload a certificate to the trustcloud server");
        System.out.println("-v filename certificate   vouch for the authenticity of an existing file in the trustcloud server using the indicated certificate");
        System.out.println("========================================================================\n");
    }
    
    
    public static void main(String[] args) throws Exception {
    	
    	/* load truststore from client */
        if (args.length < 2) {
            System.err.println("Usage: java Client truststore_filepath truststore_password");
            System.exit(1);
        }
        Client c = new Client(args[0], args[1]);
        
        /* boolean indicators for command line options */
        boolean upload = false;
        boolean fetch = false;
        boolean list = false;
        boolean upload_cert = false;
        boolean vouch = false;
        
        /* argument value of command line options */
        int circumference = -1;
        String file_to_upload = null;
        String file_to_fetch = null;
        String file_to_vouch = null;
        String cert_to_upload = null;
        String cert_to_vouch = null;
        
        /* parsing command line options */
        for(int i = 2; i < args.length; i+=2) {
            if(args[i].startsWith("-")) {
                switch (args[i].charAt(1)) {
                case 'a': 
                    if (args.length - i - 1 > 0) { // require 1 argument after -a
                        upload = true;
                        file_to_upload = args[i+1];
                    } else printCommandHelp();
                    break;
                case 'c':
                    if (args.length - i - 1 > 0) { // require 1 argument after -c
                        circumference = Integer.parseInt(args[i+1]);
                    } else printCommandHelp();
                    break;
                case 'f':
                    if (args.length - i - 1 > 0) { // require 1 argument after -f
                        fetch = true;
                        file_to_fetch = args[i+1];
                    } else printCommandHelp();
                    break;
                case 'h':
                    if (args.length - i - 1 > 0) { // require 1 argument after -h
                        c.setHost(args[i+1]);
                    } else printCommandHelp();
                    break;
                case 'l':
                    list = true;                   // require 0 argument after -l
                    i--;
                    break;
                case 'u':
                    if (args.length - i - 1 > 0) { // require 1 argument after -u
                        upload_cert = true;
                        cert_to_upload = args[i+1];
                    } else printCommandHelp();
                    break;
                case 'v':
                    if (args.length - i - 1 > 1) { // require 2 argument after -v
                        vouch = true;
                        file_to_vouch = args[i+1];
                        cert_to_vouch = args[i+2];
                        i++;
                    } else printCommandHelp();
                    break;      
                }   
            } else {	// unknown option
                printCommandHelp();
                break;
            }
        }
        
        if (c.hostport == -1) { // must have set host address and port already
            printCommandHelp();
            System.out.println("Error: problem with host address or port");
            System.exit(1);
        }
        
        if (upload) c.upload(file_to_upload, FILE);
        else if (fetch) c.fetch(file_to_fetch, circumference);
        else if (list) c.list();
        else if (upload_cert) c.upload(cert_to_upload, CERTIFICATE);
        else if (vouch) c.vouch(file_to_vouch, cert_to_vouch);
    }
    
}

