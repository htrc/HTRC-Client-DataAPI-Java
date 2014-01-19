package edu.indiana.d2i.htrc.clients.dataapi;

import gov.loc.repository.pairtree.Pairtree;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.AbstractMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * HTRCDataClient improves the memory usage by reading the Zip stream entry to
 * the buffer one by one. Sample usage is as follows.
 * <pre>
 * {@code
 * HTRCDataClient client = new HTRCDataClient.Builder(dataAPIEPR).token(token).build();
 * Iterable<Entry<String, String>> contents = client.getID2Content("id1|id2|id3");
 * Iterable<Entry<String, String>> pages = client.getID2Page("id1|id2|id3");
 * }
 * </pre>
 *
 */
public class HTRCDataClient {
    private final int BUFFER = 2048;

    // data api endpoint
    private String apiEPR = null; // e.g. https://silvermaple.pti.indiana.edu:25443/data-api/
    // deprecated usage of auth
    @Deprecated
    private String clientID, clientSecret, oauthEPR;

    // authentication
    private boolean useAuth = true;
    private boolean selfsigned = false;
    private String token = null;
    private int connectionTimeout = 0, readTimeout = 0;

    private static Pairtree pairtree = new Pairtree();

    private HttpsURLConnection httpsURLConnection = null;

    private static final Log logger = LogFactory.getLog(HTRCDataClient.class);

    // ssl stuffs
    SSLContext sslContext = null;

    private void disableSSL() throws Exception {
        if (selfsigned) {
            TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
                @Override
				public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                @Override
				public void checkClientTrusted(
                        java.security.cert.X509Certificate[] certs, String authType) {
                }

                @Override
				public void checkServerTrusted(
                        java.security.cert.X509Certificate[] certs, String authType) {
                }

                @SuppressWarnings("unused")
                public boolean isServerTrusted(
                        java.security.cert.X509Certificate[] certs) {
                    return true;
                }

                @SuppressWarnings("unused")
                public boolean isClientTrusted(
                        java.security.cert.X509Certificate[] certs) {
                    return true;
                }
            } };

            SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext
                    .getSocketFactory());
        }
    }

    /** localize all the exceptions */
    class ID2ContentIterator implements Iterator<Entry<String, String>> {
        protected ZipInputStream zipInputStream = null;
        protected ZipEntry zipEntry = null;
        protected Map.Entry<String, String> entry = null;

        public ID2ContentIterator(ZipInputStream zipinput) {
            this.zipInputStream = zipinput;
        }

        @Override
		public boolean hasNext() {
            try {
                zipEntry = zipInputStream.getNextEntry();
                if (zipEntry == null)
                    return false;

                // data api returns error file at the end of the stream
                if (zipEntry.getName().equals("ERROR.err"))
                    return false;

                ByteArrayOutputStream out = new ByteArrayOutputStream();
                int count;
                byte data[] = new byte[BUFFER];
                while ((count = zipInputStream.read(data, 0, BUFFER)) != -1) {
                    out.write(data, 0, count);
                }

                entry = new AbstractMap.SimpleEntry<String, String>(
                        zipEntry.getName(), // clean id
                        out.toString("UTF-8"));
                return true;
            } catch (Exception e) {
                logger.error(e);
                return false;
            }
        }

        @Override
		public Entry<String, String> next() {
            if (entry == null) {
                if (hasNext())
                    return next();
                else
                    return new AbstractMap.SimpleEntry<String, String>("", "");
            } else {
            		// unclean id
            		return new AbstractMap.SimpleEntry<String, String>(
            				pairtree.uncleanId(entry.getKey()), entry.getValue());
            }
        }

        @Override
		public void remove() {
            throw new UnsupportedOperationException();
        }
    }

    class ID2PageContentIterator extends ID2ContentIterator {
        private String cleanVolumeId = null;
        private String uncleanVolumeId = "";

        public ID2PageContentIterator(ZipInputStream zipinput) {
            super(zipinput);
        }

        @Override
        public Entry<String, String> next() {
            if (entry == null) // just in case
                return new AbstractMap.SimpleEntry<String, String>("", "");

            if (cleanVolumeId == null || !entry.getKey().contains(cleanVolumeId)) {
                String key = entry.getKey();
                int lastIndex = key.lastIndexOf("/");
                cleanVolumeId = (lastIndex > 0) ? key.substring(0, lastIndex) : key;
                uncleanVolumeId = pairtree.uncleanId(cleanVolumeId);
            }
            return new AbstractMap.SimpleEntry<String, String>(uncleanVolumeId,
                    entry.getValue());
        }
    }

    class ID2ContentEntry implements Iterable<Entry<String, String>> {
        private ID2ContentIterator iterator = null;

        public ID2ContentEntry(ZipInputStream zipinput) {
            this.iterator = new ID2ContentIterator(zipinput);
        }

        @Override
		public Iterator<Entry<String, String>> iterator() {
            return iterator;
        }
    }

    class ID2PageContentEntry implements Iterable<Entry<String, String>> {
        private ID2PageContentIterator iterator = null;

        public ID2PageContentEntry(ZipInputStream zipinput) {
            this.iterator = new ID2PageContentIterator(zipinput);
        }

        @Override
		public Iterator<Entry<String, String>> iterator() {
            return iterator;
        }
    }

    private InputStream request(String queryStr, boolean concat) throws Exception {
        if (selfsigned)
            disableSSL();

        // build url
        StringBuilder urlStringBuilder = new StringBuilder(apiEPR);
        urlStringBuilder.append("volumes");
        logger.debug("URL: " + urlStringBuilder.toString());

        // build body
        StringBuilder bodyBuilder = new StringBuilder();
        bodyBuilder.append("volumeIDs=").append(URLEncoder.encode(queryStr, "UTF-8"));
        if (concat)
            bodyBuilder.append("&concat=true");
        logger.debug("Body: " + bodyBuilder.toString());

        // instantiate a URL object from the URL string
        URL url = new URL(urlStringBuilder.toString());
        URLConnection urlConnection = url.openConnection();
        if (!(urlConnection instanceof HttpsURLConnection))
            throw new RuntimeException(
                    "Expect Https connection but get non https connection!");

        // typecast the generic URLConnection object to HttpsURLConnection
        httpsURLConnection = (HttpsURLConnection) urlConnection;

        // set OAUTH2 token
        httpsURLConnection.addRequestProperty("Authorization", "Bearer " + token);
        httpsURLConnection.addRequestProperty("Content-type",
                "application/x-www-form-urlencoded");

        // Request to Data API must be "POST"
        httpsURLConnection.setRequestMethod("POST");

        // must set DoOutput to true in order to write request body contents to
        // output stream
        httpsURLConnection.setDoOutput(true);

        // set time out
        httpsURLConnection.setConnectTimeout(connectionTimeout);
        httpsURLConnection.setReadTimeout(readTimeout);

        // write body content to output stream -- send the request
        OutputStream outputStream = httpsURLConnection.getOutputStream();
        PrintWriter printWriter = new PrintWriter(outputStream);
        printWriter.write(bodyBuilder.toString());
        printWriter.flush();
        printWriter.close();

        if (httpsURLConnection.getResponseCode() == 200) {
            return httpsURLConnection.getInputStream();
        } else {
            StringBuilder respBuilder = new StringBuilder();
            try {
                InputStream eStream = httpsURLConnection.getErrorStream();
                BufferedReader reader = new BufferedReader(new InputStreamReader(
                        eStream));

                String line = null;
                do {
                    line = reader.readLine();
                    if (line != null) {
                        respBuilder.append(line);
                    }
                } while (line != null);
                reader.close();
            } catch (IOException e) {
                logger.error("Unable to read response body");
            }
            logger.error(respBuilder.toString());
            throw new IOException(queryStr + " leads to fatal, rejected code "
                    + httpsURLConnection.getResponseCode());
        }
    }

    public void close() {
        if (httpsURLConnection != null) {
            httpsURLConnection.disconnect();
            httpsURLConnection = null;
        }
    }

    /**
     * Return a list of volume id and its content
     *
     * @param queryStr
     *          e.g. id1|id2|id3...
     * @return an iterable list where item includes <volumeId, volumeContent>
     * @throws Exception
     */
    public Iterable<Entry<String, String>> getID2Content(String queryStr)
            throws Exception {
        ZipInputStream zipinput = new ZipInputStream(request(queryStr, true));
        return new ID2ContentEntry(zipinput);
    }

    /**
     * Return a list of volume id and its page content
     *
     * @param queryStr
     *          e.g. id1|id2|id3...
     * @return an iterable list where item includes <volumeId, pageContent>
     * @throws Exception
     */
    public Iterable<Entry<String, String>> getID2Page(String queryStr)
            throws Exception {
        ZipInputStream zipinput = new ZipInputStream(request(queryStr, false));
        return new ID2PageContentEntry(zipinput);
    }

    private HTRCDataClient(String apiEPR, boolean useAuth, boolean selfsigned,
            String token, int connectionTimeout, int readTimeout) {
        this.useAuth = useAuth;
        this.selfsigned = selfsigned;
        this.token = token;
        this.connectionTimeout = connectionTimeout;
        this.readTimeout = readTimeout;

        this.apiEPR = (apiEPR.lastIndexOf("/") == apiEPR.length() - 1) ? apiEPR
                : apiEPR + "/";
    }

    /**
     * The client should take a token rather than client credential.
     */
    @Deprecated
    private HTRCDataClient(String apiEPR, boolean useAuth, boolean selfsigned,
            String oauthEPR, String clientId, String clientSecrete,
            int connectionTimeout, int readTimeout) {
        this.useAuth = useAuth;
        this.selfsigned = selfsigned;
        this.connectionTimeout = connectionTimeout;
        this.readTimeout = readTimeout;
        this.oauthEPR = oauthEPR;
        this.clientID = clientId;
        this.clientSecret = clientSecrete;

        this.apiEPR = (apiEPR.lastIndexOf("/") == apiEPR.length() - 1) ? apiEPR
                : apiEPR + "/";
        try {
            this.token = HTRCUtils.getToken(oauthEPR, clientId, clientSecrete);
        } catch (Exception e) {
            throw new RuntimeException(
                    String
                            .format(
                                    "Unable to obtain token from %s with clientId %s and client secrete %s",
                                    oauthEPR, clientId, clientSecrete));
        }
    }

    public static class Builder {
        private String apiEPR = HTRCConstants.DATA_API_DEFAULT_URL_PREFIX
                + HTRCConstants.DATA_API_DEFAULT_URL;
        private String delimiter = "|";

        private boolean useAuth = true;
        private String clientID, clientSecret, tokenLocation;
        private boolean selfsigned = false;
        private String token = null;
        private int connectionTimeout = 0, readTimeout = 0;

        public Builder(String apiEPR) {
            this.apiEPR = apiEPR;
        }

        public Builder selfsigned(boolean selfsigned) {
            this.selfsigned = selfsigned;
            return this;
        }

        /**
         * The client takes string concatenated with delimiter. No need to set
         * delimiter.
         */
        @Deprecated
        public Builder delimiter(String delimiter) {
            this.delimiter = delimiter;
            return this;
        }

        /**
         * Sets a specified timeout value, in milliseconds, to be used when
         * establishing a connection to the DataAPI endpoint.
         *
         * @param connectionTimeout
         *          The connection timeout, in milliseconds
         */
        public Builder connectionTimeout(int connectionTimeout) {
            this.connectionTimeout = connectionTimeout;
            return this;
        }

        /**
         * Sets a specified timeout value, in milliseconds, to be used when reading
         * from the DataAPI endpoint.
         *
         * @param readTimeout
         *          The read timeout, in milliseconds.
         */
        public Builder readTimeout(int readTimeout) {
            this.readTimeout = readTimeout;
            return this;
        }

        /**
         * Client no longer requests token itself. The token is supposed to be
         * client's input.
         */
        @Deprecated
        public Builder tokenLocation(String tokenLocation) {
            this.tokenLocation = tokenLocation;
            return this;
        }

        @Deprecated
        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        /**
         * Client no longer requests token itself. The token is supposed to be
         * client's input.
         */
        @Deprecated
        public Builder clientID(String clientID) {
            this.clientID = clientID;
            return this;
        }

        public Builder token(String token) {
            this.token = token;
            return this;
        }

        /**
         * Authentication is a requirement not an option.
         */
        @Deprecated
        public Builder authentication(boolean useAuth) {
            this.useAuth = useAuth;
            return this;
        }

        /**
         * Two ways to have authentication. Token is preferred. <br>
         * 1) token <br>
         * 2) oauth epr + client id + client secrete
         */
        public HTRCDataClient build() {
            HTRCDataClient client = null;
            if (useAuth && token != null) {
                client = new HTRCDataClient(apiEPR, true, selfsigned, token,
                        connectionTimeout, readTimeout);

            } else if (useAuth && tokenLocation != null && clientID != null
                    && clientSecret != null) {
                client = new HTRCDataClient(apiEPR, useAuth, selfsigned, tokenLocation,
                        clientID, clientSecret, connectionTimeout, readTimeout);
            } else {
                throw new IllegalArgumentException(
                        "To use authentication, either token or credential must be provide. "
                                + String
                                        .format(
                                                "Token is %s. Client id is %s, client secrete is %s , oauthEPR is %s",
                                                token, clientID, clientSecret, tokenLocation));
            }
            return client;
        }
    }

    /**
     * Help function to concatenate list of ids with delimiter.
     *
     * @param ids
     * @param delimiter
     * @return
     */
    public static String ids2URL(List<String> ids, String delimiter) {
        // StringUtil.join is preferred
        StringBuilder url = new StringBuilder();
        for (String id : ids)
            url.append(pairtree.uncleanId(id) + delimiter);
        String res = url.toString();
        return res.substring(0, res.lastIndexOf(delimiter));
    }
}