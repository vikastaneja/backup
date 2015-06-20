/*
 * Copyright, 2004-2015, SALESFORCE.com
 * All Rights Reserved
 * Company Confidential
 */

package identity.util.httplibrary;

import java.io.*;
import java.net.*;
import java.util.*;

import com.google.common.base.Strings;

import static java.net.HttpURLConnection.HTTP_SEE_OTHER;

/**
 * This class is an HTTP Utility class that encapsulated common functionality required for HTTP Requests and response
 *
 * @author vtaneja
 *
 * @since 198
 *
 */
public class HttpUtility2 {
    private CookieManager cookieManager = null;

    private HttpURLConnection connection = null;

    private static final String charset = "UTF-8";

    private static final String cookieSeparator = "; ";

    private static final String COOKIE = "Cookie";

    private static Method method = null;

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

    public static class Builder {

        private String username = null;
        private String password = null;
        private String urlString = null;

        private Method method = Method.Get;
        private List<HttpCookie> cookies = new ArrayList<HttpCookie>();
        private Map<String, String> parameters = new HashMap<String, String>();

        private boolean redirectionExpected = false;

        public Builder(final String urlString, final String username, final String password) {
            this.urlString = Strings.isNullOrEmpty(urlString) ? "" : urlString;
            this.username = Strings.isNullOrEmpty(username) ? "" : username;
            this.password = Strings.isNullOrEmpty(password) ? "" : password;
        }

        public Builder addCookie(final HttpCookie cookie) {
            this.cookies.add(cookie);
            return this;
        }

        public Builder addParameter(final String paramName, final String paramValue) {
            this.parameters.put(paramName, paramValue);
            return this;
        }

        public Builder method(Method method) {
            this.method = method;
            return this;
        }

        public Builder setAutoRedirection(boolean redirectionExpected) {
            this.redirectionExpected = redirectionExpected;
            return this;
        }

        public HttpUtility2 build() throws IOException, URISyntaxException {
            return new HttpUtility2(this);
        }
    }

    private HttpUtility2(Builder builder) throws IOException, URISyntaxException {
        this.cookieManager = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        CookieHandler.setDefault(this.cookieManager);

        this.method = method;

        StringBuffer local = new StringBuffer(builder.urlString);
        if (local.charAt(local.length() - 1) != '/') {
            local.append('/');
        }

        if (builder.method == Method.Get) {
            local.append(String.format("?un=%s&pw=%s", builder.username, builder.password)); //// HTTP GET

            if (builder.parameters != null)
            {
                for(Map.Entry<String, String> parameter : builder.parameters.entrySet()) {
                    local.append("&")
                            .append(parameter.getKey())
                            .append("=")
                            .append(parameter.getValue());
                }
            }
        }

        Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", 8080));

        if (this.connection != null) {
            throw new RuntimeException("Connection is already present");
        }

        HttpURLConnection localconnection = (new HttpConnection(local.toString(), proxy)).getConnection();

        this.connection = setupConnectionObject(builder.method, localconnection, builder.username, builder.password, builder.parameters);
        this.connection.setInstanceFollowRedirects(builder.redirectionExpected);

        setCookies(builder.cookies);
    }

    /**
     * Navigates to the URL
     * @throws IOException
     */
    public void navigate() throws IOException {
        InputStream stream = this.connection.getInputStream();
        printOutput(stream);
    }

    /**
     * Returns the HttpURLConnection object
     * @return HttpURLConnection object
     */
    public HttpURLConnection getConnection() {
        return this.connection;
    }

    /**
     * Validates that the list of cookies are also present in cookie manager
     * @param cookies to be validated
     */
    public void validateCookies(List<HttpCookie> cookies) {
        if (cookies == null || cookies.size() == 0) {
            return;
        }

        List<HttpCookie> localCookies = this.cookieManager.getCookieStore().getCookies();
        Map<String, String> map = new HashMap<String, String>();
        for (HttpCookie cookie : localCookies) {
            map.put(cookie.getName(), cookie.getValue());
        }

        for (HttpCookie cookie : cookies) {
            if (!map.containsKey(cookie.getName())) {
                throw new RuntimeException(cookie.getName() + " is not present");
            }

            if (map.get(cookie.getName()).trim().compareToIgnoreCase(cookie.getValue().trim()) != 0) {
                throw new RuntimeException(cookie.getName() + " value mismatch. Expected: " + cookie.getValue() + ", Actual: " + map.get(cookie.getName()));
            }
        }
    }

    private void setCookies(List<HttpCookie> cookies) throws URISyntaxException {
        if (cookies != null) {
            for(HttpCookie cookie : cookies) {
                this.cookieManager.getCookieStore().add(this.connection.getURL().toURI(), cookie);
            }
        }
    }

    private HttpURLConnection setupConnectionObject(Method method, HttpURLConnection connection, final String username, final String password, final Map<String, String> bodyParams) throws IOException, URISyntaxException {
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
                    .append("username=").append(URLEncoder.encode(username, charset))
                    .append("&un=").append(URLEncoder.encode(username, charset))
                    .append("&pw=").append(URLEncoder.encode(password, charset))
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

        // Else, it's likely binary content, use InputStream/OutputStream.

        response.close();
    }

    public void navigate2() throws IOException {
        if (this.connection == null) {
            throw new NullPointerException("Connection must be initialized");
        }

        this.connection.setInstanceFollowRedirects(false);
        this.navigate();

        // To handle redirects, we need to loop for each 3XX response.
        // We also need to get the Location header to get the information about the URL to redirect to
        // In addition, we need to setup all the headers, cookies to the request.
        // Also, the first time call uses the method specified, for the redirect, GET is used.
        // SID cookie comes in the response which will be the parameter to the remaining calls.

        // First get the cookie
        Map<String, List<String>> headerFields = this.connection.getHeaderFields();

        List<String> cookies = headerFields.get("Set-Cookie");
        for (String cookie : cookies) {
            System.out.println(cookie.substring(0, cookie.indexOf(";")));
        }

        List<Integer> redirectCodes = Arrays.asList(HttpURLConnection.HTTP_MOVED_PERM, HttpURLConnection.HTTP_MOVED_TEMP, HttpURLConnection.HTTP_SEE_OTHER);

        int responseCode = this.connection.getResponseCode();
        while (redirectCodes.contains(responseCode)) {

            Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", 8080));

            this.connection = (new HttpConnection(headerFields.get("Location").get(0), proxy)).getConnection();


            connection.setRequestProperty("Accept-Charset", charset);

            connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:37.0) Gecko/20100101 Firefox/37.0");
            connection.setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
            connection.setRequestProperty("Accept-Language", "en-US,en;q=0.5");
            connection.setRequestProperty("Accept-Encoding", "gzip, deflate");
            connection.setRequestProperty("Connection", "keep-alive");
            connection.setRequestProperty("Referer", "https://www.salesforce.com");
            connection.setInstanceFollowRedirects(false);

            if (System.getProperty("http.useragent") != null) connection.setRequestProperty("http.useragent", System.getProperty("http.useragent"));
            StringBuffer cookieString = new StringBuffer();
            cookieString.append("BrowserId=QLEMHpXOQ7Kiy04jKb5xYA" + cookieSeparator + "declarativeURI=edition:DB.DBEdition" + cookieSeparator);
            for (String cookie : cookies) {
                System.out.println(cookie.substring(0, cookie.indexOf(";")));
                cookieString.append(cookie + cookieSeparator);
            }

            connection.setRequestProperty(COOKIE, cookieString.toString());

            BufferedReader in = new BufferedReader(
                    new InputStreamReader(connection.getInputStream()));
            String inputLine;
            StringBuffer html = new StringBuffer();

            while ((inputLine = in.readLine()) != null) {
                html.append(inputLine);
            }
            in.close();

            System.out.println("URL Content... \n" + html.toString());
            responseCode = connection.getResponseCode();
            headerFields = this.connection.getHeaderFields();
        }

        System.out.println("DONE");
    }

    private HttpCookie getCookieObject(final String name, final String value) {
        HttpCookie cookie = new HttpCookie(name, value);
        cookie.setDomain(".salesforce.com");
        cookie.setPath("/");
        return cookie;
    }
}
