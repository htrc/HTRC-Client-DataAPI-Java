package edu.indiana.d2i.htrc.clients.dataapi;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class HTRCUtils {
	private static final Log logger = LogFactory.getLog(HTRCUtils.class);
	
	public static String getToken(String oauth2EPR, String clientId,
			String clientSecrete) throws Exception {
		String token = null;
		URL url = null;
		URLConnection urlConnection = null;
		HttpsURLConnection httpsURLConnection = null;

		try {

			// Building the OAuth2 authorization as a single URL, where client id and
			// client secret
			// are passed in as query string on the URL. They are URL encoded so
			// special characters
			// can be passed correctly
			StringBuilder urlStringBuilder = new StringBuilder(oauth2EPR);
			urlStringBuilder.append("&client_secret=").append(
					URLEncoder.encode(clientSecrete, "utf-8"));
			urlStringBuilder.append("&client_id=").append(
					URLEncoder.encode(clientId, "utf-8"));

			// instantiating a URL object from the URL string
			url = new URL(urlStringBuilder.toString());

			// open the connection to the token endpoint, and it
			// should return a URLConnection object
			urlConnection = url.openConnection();

			// sanity check: make sure the urlConnection object is
			// an HttpsURLConnection object (communication via TLS)
			assert (urlConnection instanceof HttpsURLConnection);

			// explicitly typecast the generic URLConnection object to
			// HttpsURLConnection
			httpsURLConnection = (HttpsURLConnection) urlConnection;

			// the HTTP request method must be POST
			httpsURLConnection.setRequestMethod("POST");

			// the HTTP request content-type must be application/x-www-form-urlencoded
			httpsURLConnection.addRequestProperty("content-type",
					"application/x-www-form-urlencoded");

			// must set DoOutput to true in order to write request body contents to
			// output stream
			httpsURLConnection.setDoOutput(true);

			// writing request body as an output stream
			OutputStream outputStream = httpsURLConnection.getOutputStream();
			PrintWriter printWriter = new PrintWriter(outputStream);

			// make sure the request body literally says "null", without the quotes
			// String nullBody = "null";
			String bodyString = URLEncoder.encode("grant_type", "utf-8") + "="
					+ URLEncoder.encode("client_credentials", "utf-8") + "&"
					+ URLEncoder.encode("client_id", "utf-8") + "="
					+ URLEncoder.encode(clientId, "utf-8") + "&"
					+ URLEncoder.encode("client_secret", "utf-8") + "="
					+ URLEncoder.encode(clientSecrete, "utf-8");

			// sends the request body and close the output stream
			printWriter.print(bodyString);
			printWriter.flush();
			printWriter.close();

			httpsURLConnection.connect();

			// getting the HTTP response back
			int responseCode = httpsURLConnection.getResponseCode();

			// check to make sure the response code is 200, which means OK
			if (responseCode == 200) {

				// read response body as an input stream
				InputStream inputStream = httpsURLConnection.getInputStream();
				InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
				StringBuilder responseBuilder = new StringBuilder();
				int readChar = -1;

				do {
					readChar = inputStreamReader.read();
					if (readChar >= 0) {
						responseBuilder.append((char) readChar);
					}
				} while (readChar >= 0);

				inputStreamReader.close();

				// the response body should be a JSON string
				String json = responseBuilder.toString();
				logger.info("Json: " + json);
				// parse out the access token from the JSON string
				Map<String, String> map = parseFlatOAuth2JSON(json);
				token = map.get("access_token");

				// any other response code means the OAuth2 authorization failed. throw
				// exception
			} else {
				logger.error(responseCode);
				// for other status code, the response is in the error stream
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

				logger.error("Unable to get token");
				logger.error("Response Code: " + responseCode);
				logger.error("Response: " + respBuilder.toString());
				throw new Exception("Failed to obtain OAuth2 token. Response code: "
						+ responseCode + " Response body: " + respBuilder.toString());
			}
		} finally {
			// always remember to close the connection
			if (httpsURLConnection != null) {
				httpsURLConnection.disconnect();
			}
		}

		// return the access token
		return token;
	}

	private static Map<String, String> parseFlatOAuth2JSON(String json) {
		Map<String, String> map = new HashMap<String, String>();
		StringTokenizer tokenizer = new StringTokenizer(json, ",");
		while (tokenizer.hasMoreTokens()) {
			String token = tokenizer.nextToken();
			StringTokenizer tokenizer2 = new StringTokenizer(token, ":");
			String rawProperty = tokenizer2.nextToken();
			String rawPropertyValue = tokenizer2.nextToken();

			int beginQuoteIndex = rawProperty.indexOf('"');
			int endQuoteIndex = rawProperty.lastIndexOf('"');

			String propertyName = rawProperty.substring(beginQuoteIndex + 1,
					endQuoteIndex);

			beginQuoteIndex = rawPropertyValue.indexOf('"');
			endQuoteIndex = rawPropertyValue.lastIndexOf('"');

			String propertyValue = null;

			if (beginQuoteIndex == -1) {
				propertyValue = rawPropertyValue;
			} else {
				propertyValue = rawPropertyValue.substring(beginQuoteIndex + 1,
						endQuoteIndex);
			}

			logger.info("*** " + propertyName + ":" + propertyValue);
			map.put(propertyName, propertyValue);
		}

		return map;
	}
}
