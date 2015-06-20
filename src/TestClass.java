import com.sun.deploy.net.HttpResponse;
import identity.util.httplibrary.CommonLoginOperations;
import identity.util.httplibrary.HttpUtility;
import identity.util.httplibrary.HttpUtility2;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.HttpClients;
import sun.net.www.http.HttpClient;

import javax.net.ssl.HttpsURLConnection;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.http.impl.client.HttpClientBuilder;
import java.io.InputStreamReader;
import java.io.BufferedReader;

/**
 * Created by vtaneja on 4/29/15.
 */
public class TestClass {
    public static void main(String[] args) throws IOException, URISyntaxException {

        System.out.println("Hello World!");

        URL url = new URL("http://gus.salesforce.com/");

//        HttpURLConnection httpConnection = (HttpURLConnection) url.openConnection();
//        httpConnection.setDoOutput(true);
//        httpConnection.setDoInput(true);
//        httpConnection.setRequestMethod("GET");
//        httpConnection.setRequestProperty("charset", "utf-8");
//        httpConnection.setRequestProperty("Cookie", "name1=value1; name2=value2");
//        httpConnection.addRequestProperty("blah", "blah");
//        httpConnection.setInstanceFollowRedirects(true);
//        System.out.println("Method: " + httpConnection.getRequestMethod());
//        OutputStreamWriter stream = new OutputStreamWriter(httpConnection.getOutputStream());
//
//        System.out.println("Output code: " + httpConnection.getResponseCode());
//        System.out.println("Response message: " + httpConnection.getResponseMessage());
//        stream.close();

//        Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", 8080));
//        CookieHandler.setDefault(new CookieManager(null, CookiePolicy.ACCEPT_ALL));
        String charset = "UTF-8";
////        String query = String.format("un=%s&pw=%s", URLEncoder.encode("vtaneja@test.com", charset), URLEncoder.encode("test12345", charset)); //// HTTP GET
//        String urlString = "https://na7-blitz01.soma.salesforce.com/";
//        Map<String, String> properties = new HashMap<String, String>();
//        properties.put("un", "vtaneja@test.com");
//        properties.put("pw", "test12345");
//        properties.put("Cookie", "QCQQ=AAAAAAA");
//        try {
//            InputStream inputStream = HttpUtility.NavigateToUrl(urlString, HttpUtility.Method.Post, properties, true);
//        }
//        catch (IOException ex) {
//            System.out.println("HTTP Error: " + ex.getLocalizedMessage());
//        }

//        URL url1 = new URL("http", "vtaneja-ltm01.internal.salesforce.com", 6109, "?un=vtaneja@test.com&pw=123456");
//        URL url2 = new URL("http://vtaneja-ltm01.internal.salesforce.com:6109/?un=vtaneja@test.com&pw=123456");

         String username = "vtaneja@test.com";
//        String username = "admin@722349260482994.com";
        String password = "test12345";
//        String urlString = "https://na1-blitz02.soma.salesforce.com/";
//        String urlString = "http://vtaneja-wsl01.internal.salesforce.com:6109/";
                 String urlString = "https://na7-blitz01.soma.salesforce.com/";
//         String urlString = "http://vtaneja-wsl01.internal.salesforce.com:6109";
//        CommonLoginOperations.RunAll(urlString, username, password, HttpUtility2.Method.Get);
        CommonLoginOperations.RunAll(urlString, username, password, HttpUtility2.Method.Post);
        url = new URL("https://na7-blitz01.soma.salesforce.com");// + query);

        //////////////////////////////////////////////****************
//        HttpsURLConnection httpsConnection = (HttpsURLConnection) url.openConnection();
//
//
//        httpsConnection.setDoOutput(true); //// HTTP POST
//        httpsConnection.setDoInput(true);
//        httpsConnection.setRequestMethod("POST"); //// HTTP POST
//
//        //updateMethod(httpsConnection);
//        httpsConnection.setRequestProperty("Accept-Charset", charset);
//
////        httpsConnection.addRequestProperty("username", URLEncoder.encode("vtaneja@test.com", charset));
////        httpsConnection.addRequestProperty("pw", URLEncoder.encode("test12345", charset));
//        httpsConnection.setRequestProperty("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:37.0) Gecko/20100101 Firefox/37.0");
//        httpsConnection.setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
//        httpsConnection.setRequestProperty("Accept-Language", "en-US,en;q=0.5");
//        httpsConnection.setRequestProperty("Accept-Encoding", "gzip, deflate");
//        httpsConnection.setRequestProperty("Connection", "keep-alive");
//        httpsConnection.setInstanceFollowRedirects(false);
//        httpsConnection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=" + charset); //// HTTP POST
//
////        httpsConnection.setRequestProperty("Cookie", "QCQQ=AAAAAAAA");
//        httpsConnection.setRequestProperty("Cookie", "BrowserId=QLEMHpXOQ7Kiy04jKb5xYA"); //// HTTP POST
//        httpsConnection.setRequestProperty("Cookie", "declarativeURI=edition:DB.DBEdition"); //// HTTP POST
//        //httpsConnection.connect();
////        httpsConnection.setRequestProperty("Cookie", "name1=value1; name2=value2");
////        httpsConnection.addRequestProperty("blah", "blah");
//        System.out.println("HTTPS");
//        System.out.println("Method: " + httpsConnection.getRequestMethod());
//
//        //// Required only in case HTTP POST
//        OutputStreamWriter out = new OutputStreamWriter(httpsConnection.getOutputStream());
//
//        String data = "username=" + URLEncoder.encode("vtaneja@test.com", charset) + "&" +
//            "un=" + URLEncoder.encode("vtaneja@test.com", charset) + "&" +
//            "pw=" + URLEncoder.encode("test12345", charset) + "&" +
//            "useSecure=true" + "&" +
//            "Login=";
//
//        out.write(data);
//
//        out.flush();
//        out.close();
//        //// ENd of Required only in case HTTP POST
//
//        if (System.getProperty("http.useragent") != null) httpsConnection.setRequestProperty("http.useragent", System.getProperty("http.useragent"));
//
//        //httpsConnection.setRequestProperty("http.useragent", );
////        OutputStreamWriter stream1 = new OutputStreamWriter(httpsConnection.getOutputStream());
//        InputStream response = httpsConnection.getInputStream();
//        int status = httpsConnection.getResponseCode();
//        System.out.println("Output code: " + status);
//        System.out.println("Response message: " + httpsConnection.getResponseMessage());
//
//        for (Map.Entry<String, List<String>> header : httpsConnection.getHeaderFields().entrySet()) {
//            System.out.println(header.getKey() + "=" + header.getValue());
//        }
//
//        String contentType = httpsConnection.getHeaderField("Content-Type");
//        charset = null;
//
//        for (String param : contentType.replace(" ", "").split(";")) {
//            if (param.startsWith("charset=")) {
//                charset = param.split("=", 2)[1];
//                break;
//            }
//        }
//
//        if (charset != null) {
//            try (BufferedReader reader = new BufferedReader(new InputStreamReader(response, charset))) {
//                for (String line; (line = reader.readLine()) != null;) {
//                    System.out.println(line);
//                }
//            }
//        }
//        else {
//            // It's likely binary content, use InputStream/OutputStream.
//        }
////        stream1.close();
//        response.close();
/*
        CloseableHttpClient client = HttpClients.createDefault();
        HttpPost post = new HttpPost("http://www.salesforce.com");
        HttpResponse response = client.execute(post);
*/

    }

    private static void updateMethod(HttpURLConnection connection) throws ProtocolException {
        connection.setRequestMethod("GET");
    }
}

