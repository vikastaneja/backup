package identity.util.httplibrary;

import javax.net.ssl.*;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Created by vtaneja on 5/11/16.
 */
public class HttpsUtility {

    public static void main(String [] args) throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException, KeyManagementException {
        URL url = new URL("https://tls1test.salesforce.com/s/");
        HttpsURLConnection connection = (HttpsURLConnection)url.openConnection();
        String algorithm = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(algorithm);
//        KeyStore ks = openKeyStore(System.getProperty("app.home") + "/conf/sfdc.keystore", "testing123", "PKCS12");
        KeyStore ks = KeyStore.getInstance("JKS");
        FileInputStream fis = new FileInputStream("testkey.jks");
        char[] password = "password".toCharArray();
        ks.load(fis, password);
        tmf.init(ks);
        SSLContext sc = SSLContext.getInstance("TLSv1");
        // Init the SSLContext with a TrustManager[] and SecureRandom()
        sc.init(null, getTrustManagers(), new java.security.SecureRandom());
        connection.setSSLSocketFactory(sc.getSocketFactory());
        AtomicBoolean connectionSuccessful = new AtomicBoolean();
        connectionSuccessful.set(true);
        try {
            connection.connect();
        } catch (javax.net.ssl.SSLHandshakeException ex) {
            connectionSuccessful.set(false);
            System.out.println("Exception: Failed to connect - " + ex.getMessage());
        } finally {
            connection.disconnect();
        }

        if (connectionSuccessful.get()) {
            if (connection.getResponseCode() == -1) {
                System.out.println("Failed to connect" + connection.getResponseMessage());
            } else {
                System.out.println("Connection successful with HTTP returned code: " + connection.getResponseCode()
                        + ", Response message: " + connection.getResponseMessage());
            }
        }
        System.out.println();
        connection.disconnect();
    }

    private static KeyStore openKeyStore(String pkcs12File, String password, String type) throws IOException,
            NoSuchAlgorithmException, KeyStoreException, CertificateException {
        ByteArrayInputStream fin = null;
        char[] passphrase = password.toCharArray();
        KeyStore ks = KeyStore.getInstance(type);
        fin = new ByteArrayInputStream(FileUtil.readAsByteArray(new File(pkcs12File)));
        ks.load(fin, passphrase);
        return ks;
    }

    private static TrustManager[] getTrustManagers() throws NoSuchAlgorithmException, KeyStoreException {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

        trustManagerFactory.init((KeyStore) null);

        System.out.println("JVM Default Trust Managers:");
        for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
            System.out.println(trustManager);

            if (trustManager instanceof X509TrustManager) {
                X509TrustManager x509TrustManager = (X509TrustManager)trustManager;
                System.out.println("\tAccepted issuers count : " + x509TrustManager.getAcceptedIssuers().length);
            }
        }

        return trustManagerFactory.getTrustManagers();
    }
}
