/*
 * Copyright, 2004-2015, SALESFORCE.com
 * All Rights Reserved
 * Company Confidential
 */

package identity.util.httplibrary;

import java.io.*;
import java.net.*;
import java.util.List;
import java.util.Map;

import com.google.common.base.Strings;


/**
 * This class is an HTTP Utility class that encapsulated common functionality required for HTTP Requests and response
 *
 * @author vtaneja
 *
 * @since 198
 *
 */
public final class HttpUtility {

    private CookieManager cookieManager = null;

    private HttpURLConnection connection = null;

    private static final String charset = "UTF-8";

    private static final String cookieSeparator = "; ";

    public static final String COOKIE = "Cookie";

    public static final String UN_STRING = "un";

    public static final String PW_STRING = "pw";

    /**
     * Enum for HTTP methods
     * Currently it has enums for GET and POST only
     */
    public enum Method {
        Get ("GET"),
        Post ("POST");

        private final String method;
        private Method(String m_name) {
            method = m_name;
        }

        public boolean equalsMethod(String m) {
            if (Strings.isNullOrEmpty(m)) {
                return false;
            }

            return method.equals(m);
        }

        @Override
        public String toString() {
            return method;
        }
    }


    /**
     * The function:
     * 1. Sets up the Cookie as part of the properties parameter
     * 2. Sets up the username and password, passed as part of properties parameter
     * 3. Sets up optional body parameters, passed as part of bodyParams
     * 4. Use the HTTP method to navigate to URL
     * Note that it sets up the auto redirection to false
     * @param urlString - URL to navigate to
     * @param method - HTTP Method to use
     * @param properties - username, password
     * @param bodyParams - optional body parameters
     * @return InputStream as returned by the HttpURLConnection object, upon successful connection
     * @throws IOException
     */
    public void NavigateToUrl(final String urlString, Method method, final Map<String, String> properties, final Map<String, String> bodyParams, final List<HttpCookie> cookies) throws IOException, URISyntaxException {
        this.NavigateToUrl(urlString, method, properties, bodyParams, cookies, false);
    }

    /**
     * The function:
     * 1. Sets up the Cookie as part of the properties parameter
     * 2. Sets up the username and password, passed as part of properties parameter
     * 3. Sets up optional body parameters, passed as part of bodyParams
     * 4. Use the HTTP method to navigate to URL
     * 5. Set the auto redirection flag
     * @param urlString - URL to navigate to
     * @param method - HTTP Method to use
     * @param credentials - username, password
     * @param bodyParams - optional body parameters like QCQQ, etc.
     * @param redirectExpected - true if auto redirection is expected, false otherwise.
     * @return InputStream as returned by the HttpURLConnection object, upon successful connection
     * @throws IOException
     */
    public void NavigateToUrl(final String urlString, Method method, final Map<String, String> credentials, final Map<String, String> bodyParams, final List<HttpCookie> cookies, boolean redirectExpected) throws IOException, URISyntaxException {
        if (Strings.isNullOrEmpty(urlString)) {
            throw new RuntimeException("Url string is null or empty");
        }

        this.cookieManager = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        CookieHandler.setDefault(this.cookieManager);


        StringBuffer local = new StringBuffer(urlString);
        if (local.charAt(local.length() - 1) != '/') {
            local.append('/');
        }

        if (method == Method.Get) {
            if (credentials != null && credentials.containsKey(UN_STRING) && credentials.containsKey(PW_STRING)) {
                local.append(String.format("?un=%s&pw=%s", credentials.get(UN_STRING), credentials.get(PW_STRING))); //// HTTP GET
            }

            if (bodyParams.containsKey("QCQQ")) {
                local.append("&QCQQ=").append(bodyParams.get("QCQQ"));
            }
        }

        Proxy proxy = null; //new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", 8080));

        if (this.connection != null) {
            throw new RuntimeException("Connection is already present");
        }

        HttpURLConnection localconnection = (new HttpConnection(local.toString(), proxy)).getConnection();

        this.connection = setupConnectionObject(method, localconnection, credentials, bodyParams);
        this.connection.setInstanceFollowRedirects(redirectExpected);

        setCookies(cookies);

        InputStream stream = this.connection.getInputStream();
        printOutput(stream);
    }

    private void setCookies(List<HttpCookie> cookies) throws URISyntaxException {
        if (cookies != null) {
            for(HttpCookie cookie : cookies) {
                this.cookieManager.getCookieStore().add(this.connection.getURL().toURI(), cookie);
            }
        }
    }

    private HttpURLConnection setupConnectionObject(Method method, HttpURLConnection connection, final Map<String, String> params, final Map<String, String> bodyParams) throws IOException, URISyntaxException {
        if (connection == null) {
            return null;
        }

        connection.setRequestProperty("Accept-Charset", charset);

        connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:37.0) Gecko/20100101 Firefox/37.0");
        connection.setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        connection.setRequestProperty("Accept-Language", "en-US,en;q=0.5");
        connection.setRequestProperty("Accept-Encoding", "gzip, deflate");
        connection.setRequestProperty("Connection", "keep-alive");
        connection.setInstanceFollowRedirects(false);

        if (System.getProperty("http.useragent") != null) connection.setRequestProperty("http.useragent", System.getProperty("http.useragent"));
        String cookieString = "BrowserId=QLEMHpXOQ7Kiy04jKb5xYA" + cookieSeparator + "declarativeURI=edition:DB.DBEdition";
        connection.setRequestProperty(COOKIE, cookieString);

        if (method == Method.Post) {
            connection.setRequestMethod(method.toString());
            connection.setDoOutput(true); //// HTTP POST
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=" + charset); //// HTTP POST

            //// Required only in case HTTP POST
            OutputStreamWriter out = new OutputStreamWriter(connection.getOutputStream());

            StringBuilder sb = new StringBuilder()
                    .append("username=").append(URLEncoder.encode(params.get(UN_STRING), charset))
                    .append("&un=").append(URLEncoder.encode(params.get(UN_STRING), charset))
                    .append("&pw=").append(URLEncoder.encode(params.get(PW_STRING), charset))
                    .append("&useSecure=true")
                    .append("&Login=");

            if (bodyParams != null) {
                for (Map.Entry<String, String> param : bodyParams.entrySet()) {
                    if (sb.length() != 0) sb.append("&");
                    sb.append(param.getKey()).append("=").append(param.getValue());
                }
            }

            out.write(sb.toString());

            out.flush();
            out.close();
        }

        return connection;
    }

    public HttpURLConnection getConnection() {
        return this.connection;
    }

    public void ValidateHeaders(Map<String, String> expectedHeaders) {
        if (expectedHeaders == null) {
            throw new RuntimeException("Header map is null");
        }

        if (expectedHeaders.size() == 0) {
            System.out.println("Nothing to validate...");
            return;
        }

        if (this.connection == null) {
            throw new RuntimeException("No connection is present");
        }

        Map<String, List<String>> headerFields = this.connection.getHeaderFields();

        for (Map.Entry<String, String> header : expectedHeaders.entrySet()) {
            String key = header.getKey();
            if (!headerFields.containsKey(key)) {
                throw new RuntimeException(String.format("Header %s is not present", key));
            }
        }
    }

    public void ValidateCookies(Map<String, String> expectedCookies) {
        if (expectedCookies == null) {
            throw new RuntimeException("Header map is null");
        }

        if (expectedCookies.size() == 0) {
            System.out.println("Nothing to validate...");
            return;
        }

        if (this.connection == null) {
            throw new RuntimeException("No connection is present");
        }

        String cookieHeader = "Set-Cookie";
        if (!this.connection.getHeaderFields().containsKey(cookieHeader)) {
            System.out.println("No cookie is returned from the server");
            return;
        }

        Map<String, List<String>> headerFields = this.connection.getHeaderFields();

    }

    public void ValidateParameters(Map<String, String> expectedParameters) {

    }

    private void printOutput(InputStream response) throws IOException {
        if (this.connection == null) {
            System.out.println("Connection object is null");
            return;
        }

        int status = this.connection.getResponseCode();
        System.out.println("Output code: " + status);
        System.out.println("Response message: " + this.connection.getResponseMessage());

        for (Map.Entry<String, List<String>> header : this.connection.getHeaderFields().entrySet()) {
            System.out.println(header.getKey() + "=" + header.getValue());
        }

        String contentType = this.connection.getHeaderField("Content-Type");
        String localcharset = null;

        for (String param : contentType.replace(" ", "").split(";")) {
            if (param.startsWith("charset=")) {
                localcharset = param.split("=", 2)[1];
                break;
            }
        }

        if (localcharset != null) {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(response, localcharset))) {
                for (String line; (line = reader.readLine()) != null;) {
                    System.out.println(line);
                }
            }
        }
        else {
            // It's likely binary content, use InputStream/OutputStream.
        }

        response.close();
    }
}
