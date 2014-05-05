import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;


public class SSLUtilities {
	public static SSLSocketFactory getSSLSocketFactory(String trustFile, String password) throws Exception {

        FileInputStream fis = new FileInputStream(trustFile);
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(fis, password.toCharArray());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        SSLContext ctx = SSLContext.getInstance("SSL");
        ctx.init(null, tmf.getTrustManagers(), null);

        return ctx.getSocketFactory();
    }

    public static SSLServerSocketFactory getSSLServerSocketFactory(String keyFile, String password) throws Exception {
        
        FileInputStream fis = new FileInputStream(keyFile);
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(fis, password.toCharArray());
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, password.toCharArray());
        SSLContext ctx = SSLContext.getInstance("SSL");
        ctx.init(kmf.getKeyManagers(), null, null);
        
        return ctx.getServerSocketFactory();
    }



    public static void readFile(SSLSocket connection, OutputStream output) throws Exception {
        
        DataInputStream dis = new DataInputStream(connection.getInputStream());
        long fileLength = dis.readLong();
        if (fileLength == -1) {
            return;
        }
        for (long l = 0; l < fileLength; ++l) {
            output.write(dis.read());
        }
        dis.close();
    }

    public static void writeFile(SSLSocket connection, File file) throws Exception {
        
        DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
        long fileSize = file.length();
        dos.writeLong(fileSize);
        FileInputStream fis = new FileInputStream(file);
        for (long l = 0; l < fileSize; ++l) {
            dos.write(fis.read());
        }
        fis.close();
        
    }
}
