import java.io.*;
import java.net.InetSocketAddress;
import java.lang.*;
import java.net.URL;
import com.sun.net.httpserver.HttpsServer;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import com.sun.net.httpserver.*;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;

import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URLConnection;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.swing.plaf.synth.SynthEditorPaneUI;
import java.security.cert.X509Certificate;

import java.net.InetAddress;
import java.util.Random;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsExchange;

public class LocalHttpsServer {

    private static HttpsServer httpsServer = null;
    private static Random rand = new Random(System.currentTimeMillis());
    public static class MyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
            boolean stop = false;
            int random = Math.abs(rand.nextInt() % 1000);
            String response = "This is the response" + random + "\n";
            System.out.println("===> " + random);
            HttpsExchange httpsExchange = (HttpsExchange) t;
            if (t.getRequestHeaders().containsKey("Stop")) stop = true;
            t.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
            t.getResponseHeaders().add("Cookie:", "$Version=1; Skin=new;");
            t.sendResponseHeaders(200, response.length());
            OutputStream os = t.getResponseBody();
            os.write(response.getBytes());
            os.close();
            if (stop) httpsServer.stop(1);
        }
    }

    /**
     * @param args
     */
    public static void main(String[] args) throws Exception {

        try {
            String currentDirectory;
            File file = new File(".");
            currentDirectory = file.getAbsolutePath();
            System.out.println("Current working directory : "+currentDirectory);

            // setup the socket address
            int port = rand.nextInt() % 10000;
            port = Math.abs(port) < 1000 ? 1000 + Math.abs(port) : Math.abs(port);
//            System.out.println("===> Starting server at " + port + " port");
            InetSocketAddress address = new InetSocketAddress(0);

            // initialise the HTTPS server
            httpsServer = HttpsServer.create(address, 0);
            SSLContext sslContext = SSLContext.getInstance("TLS");

            System.out.println("===> Starting server at " + httpsServer.getAddress().getPort() + " port");
            // initialise the keystore
            char[] password = "password".toCharArray();
            KeyStore ks = KeyStore.getInstance("JKS");
            FileInputStream fis = new FileInputStream("testkey.jks");
            ks.load(fis, password);

            // setup the key manager factory
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, password);

            // setup the trust manager factory
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(ks);

            // setup the HTTPS context and parameters
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
                public void configure(HttpsParameters params) {
                    try {
                        // initialise the SSL context
                        SSLContext c = SSLContext.getDefault();
                        SSLEngine engine = c.createSSLEngine();
                        params.setNeedClientAuth(false);
                        params.setCipherSuites(engine.getEnabledCipherSuites());
                        String[] protocols = engine.getEnabledProtocols();
                        params.setProtocols(new String[] {"TLSv1.1"});

                        // get the default parameters
                        SSLParameters defaultSSLParameters = c.getDefaultSSLParameters();
                        params.setSSLParameters(defaultSSLParameters);

                    } catch (Exception ex) {
                        System.out.println("Failed to create HTTPS port");
                    }
                }
            });
            httpsServer.createContext("/", new MyHandler());
            httpsServer.setExecutor(null); // creates a default executor
            httpsServer.start();

        } catch (Exception exception) {
            System.out.println("Failed to create HTTPS server on port " + 8000 + " of localhost");
            exception.printStackTrace();

        }
    }

}