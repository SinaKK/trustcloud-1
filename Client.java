import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;


public class Client {
	private SSLSocketFactory sslSocket;
	private String hostaddress;
	private int hostport = -1;
	
    public Client(String trustFile, String password) throws Exception {
    	sslSocket = (SSLSocketFactory) SSLUtilities.getSSLSocketFactory(trustFile, password);
    }
        
    public void upload(String filename) throws Exception {
    	SSLSocket connection = (SSLSocket) sslSocket.createSocket(hostaddress, hostport);
    	DataInputStream dis = new DataInputStream(connection.getInputStream());
    	DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
    	File f = new File(filename);
    	dos.writeUTF("UPLOAD"); 	// write command
    	dos.writeUTF(f.getName()); 	// write file name
    	
    	SSLUtilities.writeFile(connection, f); 	// write the file
    	if (dis.readBoolean()) {	// read boolean
    		System.out.println("\"" + filename + "\" upload success.");	
    	} else {
    		System.out.println("\"" + filename + "\" upload fail.");
    	}
    	
    	dis.close();
    	connection.close();
    }

    private void setCircumference(int c) {
    	return;
    }
    
    private void fetch(String filename) throws Exception {
    	SSLSocket connection = (SSLSocket) sslSocket.createSocket(hostaddress, hostport);
    	DataInputStream dis = new DataInputStream(connection.getInputStream());
    	DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
    	dos.writeUTF("FETCH"); 		// write command
    	dos.writeUTF(filename); 	// write filename
    	if (dis.readBoolean()) {	// read if the server has the file
    		System.out.println("Reading \"" + filename + "\".........");
    		SSLUtilities.readFile(connection, System.out);
    		System.out.println();
    	} else {
    		System.out.println("The server does not has the file.");
    	}
    	dis.close();
    	dos.close();
    	connection.close();
    }
    
    private void uploadCert(String filename) {
    	return;
    }
    
    private void list() {
    	return;
    }
    
    private void vouch(String filename, String Cert) {
    	return;
    }
    
    private void setHost(String hostaddress) {
    	int seperate = hostaddress.indexOf(":");
    	this.hostaddress = hostaddress.substring(0, seperate);
    	this.hostport = Integer.parseInt(hostaddress.substring(seperate+1));
    }
    
    
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
		if (args.length < 2) {
            System.err.println("Usage: java Client truststore_filepath truststore_password");
            System.exit(1);
        }
		String truststore = args[0];
        String password = args[1];
        
        Client c = new Client(truststore, password);
        
        /* boolean indicator for activities */
        boolean upload = false;
        boolean fetch = false;
        boolean list = false;
        boolean upload_cert = false;
        boolean vouch = false;
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
        			if (args.length - i - 1 > 0) { // require 1 argument after the option
        				upload = true;
        				file_to_upload = args[i+1];
        			}
        			else printCommandHelp();
        			break;
        		case 'c':
        			if (args.length - i - 1 > 0) { // require 1 argument after the option
        				c.setCircumference(Integer.parseInt(args[i+1]));
        			}
        			else printCommandHelp();
        			break;
        		case 'f':
        			if (args.length - i - 1 > 0) { // require 1 argument after the option
        				fetch = true;
        				file_to_fetch = args[i+1];
        			}
        			else printCommandHelp();
        			break;
        		case 'h':
        			if (args.length - i - 1 > 0) { // require 1 argument after the option
        				c.setHost(args[i+1]);
        			}
        			else printCommandHelp();
        			break;
        		case 'l':
        			list = true;				   // require no argument after the option
        			i--;
        			break;
        		case 'u':
        			if (args.length - i - 1 > 0) { // require 1 argument after the option
        				c.uploadCert(args[i+1]);
        			}
        			else printCommandHelp();
        			break;
        		case 'v':
        			if (args.length - i - 1 > 1) { // require 2 argument after the option
        				vouch = true;
        				file_to_vouch = args[i+1];
        				cert_to_vouch = args[i+2];
        				i++;
        			}
        			else printCommandHelp();
        			break;		
        		}	
        	} else {
        		printCommandHelp();
        		break;
        	}
        }
        
        if (c.hostport == -1) { // must have set host address and port already
        	printCommandHelp();
        	System.out.println("Error: problem with host address or port");
        	System.exit(1);
        }
        
        if (upload) c.upload(file_to_upload);
        if (fetch) c.fetch(file_to_fetch);
        if (list) c.list();
        if (upload_cert) c.uploadCert(cert_to_upload);
        if (vouch) c.vouch(file_to_vouch, cert_to_vouch);
	}
    
}

