import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.RandomAccessFile;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;


public class KeyReader {

	public static PrivateKey readPrivateKey(String filename) throws Exception {
		RandomAccessFile raf = new RandomAccessFile(filename, "r");
    	byte[] buf = new byte[(int)raf.length()];
    	raf.readFully(buf);
    	raf.close();
    	PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(buf);
    	KeyFactory kf = KeyFactory.getInstance("RSA");
    	PrivateKey privateKey = kf.generatePrivate(kspec);
    	return privateKey;
	}
	
	public static byte[] signData(String data, PrivateKey key) throws Exception {

		Signature signature = Signature.getInstance("SHA256withRSA"); 
    	signature.initSign(key);
    	byte[] dataInBytes = data.getBytes();  
    	
        signature.update(dataInBytes);  
        byte[] signedData = signature.sign();
        return signedData;
	}
	
	public static boolean verify(byte[] originData, byte[] signedData, Certificate cert) throws Exception {
		Signature verifySig = Signature.getInstance("SHA256withRSA");  
        verifySig.initVerify(cert);  
        verifySig.update(originData);
        return verifySig.verify(signedData);  
	}
	
	
	public static void main(String[] args) throws Exception {
		String data = "dfklajsdklfkjlsadljfkljkasdfjklslkdfjlkasdjflkasjflksdajflksadjfkqwjeporiusdlfjhasldkjflaskdjflaksdjflasdjflskdjfsldkfjlksadfjlksjdflkasjdflksjdflkjsadf";
		String keyFile = "certs/key.pk8";
		String rightCertFile = "certs/Aole.crt";
		String wrongCertFile = "certs/Hita.crt";
		
		File wf = new File(wrongCertFile);
    	CertificateFactory wcf = CertificateFactory.getInstance("X.509");
    	BufferedInputStream win = new BufferedInputStream(new FileInputStream(wf));
    	Certificate wrongCert = wcf.generateCertificate(win);
    	win.close();
    	
		File rf = new File(rightCertFile);
		CertificateFactory rcf = CertificateFactory.getInstance("X.509");
    	BufferedInputStream rin = new BufferedInputStream(new FileInputStream(rf));
    	Certificate rightCert = rcf.generateCertificate(rin);
    	rin.close();
		
		if (!verify(data.getBytes(), signData(data, readPrivateKey(keyFile)), wrongCert)) {
			System.out.println("Hita.crt is the wrong certificate");
		}
		
		if (verify(data.getBytes(), signData(data, readPrivateKey(keyFile)), rightCert)) {
			System.out.println("Aole.crt is the right certificate");
		}
		
	
	}
}