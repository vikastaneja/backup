/*
 * Copyright, 2004-2015, SALESFORCE.com
 * All Rights Reserved
 * Company Confidential
 */

package identity.util.httplibrary;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import com.google.common.base.Strings;

/**
 *
 * Class for basic HTTP interaction.
 *
 * @author vtaneja
 * @since 198
 */
public final class HttpConnection {

    private final HttpURLConnection connection;

    /**
     * Constructor for HttpMethods class
     * @param url string for the server to connect to
     * @throws IOException
     */
    public HttpConnection(final String url) throws IOException {
        if (Strings.isNullOrEmpty(url)) {
            throw new RuntimeException("url string is null or empty");
        }

        this.connection = this.getConnectionObject(url, null);
        this.connection.setInstanceFollowRedirects(true);
    }

    /**
     * Constructor for HttpMethods class
     * @param url string for the server to connect to
     * @param proxy Proxy to be used
     * @throws IOException
     */
    public HttpConnection(final String url, final Proxy proxy) throws IOException {
        if (Strings.isNullOrEmpty(url)) {
            throw new RuntimeException("url string is null or empty");
        }

        this.connection = this.getConnectionObject(url, proxy);
        this.connection.setInstanceFollowRedirects(true);
    }

    /**
     * Gets the active connection for the class. The redirect is set to true for this connection object.
     * @return HttpURLConnection
     */
    public HttpURLConnection getConnection() {
        return this.connection;
    }


    private HttpURLConnection getConnectionObject(final String urlString, final Proxy proxy) throws IOException {
        if (Strings.isNullOrEmpty(urlString)) {
            throw new RuntimeException("url string is null or empty");
        }

        URL url = new URL(urlString);
        if (proxy != null) {
            return (HttpURLConnection) url.openConnection(proxy);
        }

        return (HttpURLConnection) url.openConnection();
    }
}
