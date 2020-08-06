/*
 * Copyright (C) 2020 Max 'Libra' Kersten [@LibraAnalysis, https://maxkersten.nl]
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package malshareapi;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

/**
 * The MalShare malware dataset is accessible via an API. To avoid recreating a
 * handler for this API by several people, one can use this class. The Apache
 * HTTP Components dependency is the sole dependency that is used within this
 * class, aside from generic Java classes that are not depending on any
 * dependency nor Java runtime version.
 *
 * mvn clean compile assembly:single
 *
 * @author Max 'Libra' Kersten [@LibraAnalysis, https://maxkersten.nl]
 */
public class MalShareApi {

    /**
     * The base URL of the API, to which specific API actions can be appended
     */
    private final String apiBase;

    /**
     * To interact with the API, a valid API key is required. All API endpoints
     * are covered by the public functions in this class. To minimise the needed
     * dependencies, JSON responses are returned in the form of a string. Files
     * are returned as byte arrays.
     *
     * The IOException that is possibly thrown by any API call contains a useful
     * error message to use/provide to the user.
     *
     * @param apiKey a valid MalShare API key
     */
    public MalShareApi(String apiKey) {
        //Set the API base
        apiBase = "https://malshare.com/api.php?api_key=" + apiKey + "&action=";
    }

    /**
     * Performs a generic HTTP GET request to the given URL. The response is
     * returned as a byte array, which can be converted into several data types,
     * depending on the expected outcome.
     *
     * @param appendix the URL to request
     * @return the web server's response in the form of a byte array
     * @throws IOException if anything goes wrong with the HTTP GET connection
     */
    private byte[] get(String appendix) throws IOException {
        //Create the request based on the URL
        HttpGet request = new HttpGet(apiBase + appendix);
        //Create a HTTP client
        CloseableHttpClient httpClient = HttpClients.createDefault();
        //Execute the request
        CloseableHttpResponse responseObject = httpClient.execute(request);
        //Get the response
        HttpEntity responseEntity = responseObject.getEntity();

        //Read the response, although the size is unknown, its read in chunks of 1024 bytes
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int offset;
        byte[] data = new byte[1024];
        while ((offset = responseEntity.getContent().read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, offset);
        }
        //Flush the buffer
        buffer.flush();
        //Return the byte array
        return buffer.toByteArray();
    }

    /**
     * Performs a generic HTTP POST request based on the given request. The
     * response is returned as a byte array, which can be converted into several
     * data types, depending on the expected outcome.
     *
     * @param request the request object to which the POST request needs to be
     * made
     * @return the web server's response in the form of a byte array
     * @throws IOException if anything goes wrong with the HTTP POST connection
     */
    private byte[] post(String appendix, MultipartEntityBuilder builder) throws IOException {
        //Create a HTTP client
        CloseableHttpClient httpClient = HttpClients.createDefault();
        //Create a HTTP post object for the given URL
        HttpPost httpPost = new HttpPost(apiBase + appendix);
        //Get the multipart builder's build
        HttpEntity multipart = builder.build();
        //Set the newly built multipart object
        httpPost.setEntity(multipart);
        //Execute the HTTP POST request
        CloseableHttpResponse response = httpClient.execute(httpPost);
        //Get the response
        HttpEntity responseEntity = response.getEntity();

        //Read the response in chunks of 1024 bytes
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int offset;
        byte[] data = new byte[1024];
        while ((offset = responseEntity.getContent().read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, offset);
        }
        //Flush the buffer
        buffer.flush();
        //Return the byte array
        return buffer.toByteArray();

    }

    /**
     * List hashes from the past 24 hours in plain text or JSON, depending on
     * the boolean's value.
     *
     * Note that the JSON format is still returned in a String object. This is
     * done to allow the user of this library to use whatever JSON parser is
     * already in use, instead of using two different ones.
     *
     * @param json true if the hashes from the past 24 hours should be in JSON
     * format, false if it should be in plain text
     * @return a list of the hashes of the last 24 hours in the requested format
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public String getList(boolean json) throws IOException {
        if (json) {
            return new String(get("getlist"));
        } else {
            return new String(get("getlistraw"));
        }
    }

    /**
     * Gets a list of sample sources from the past 24 hours in plain text or
     * JSON, depending in the boolean's value.
     *
     * Note that the JSON format is still returned in a String object. This is
     * done to allow the user of this library to use whatever JSON parser is
     * already in use, instead of using two different ones.
     *
     * @param json true if the sample sources from the past 24 hours should be
     * in JSON format, false if it should be in plain text
     * @return a list o
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public String getSources(boolean json) throws IOException {
        if (json) {
            return new String(get("getsources"));
        } else {
            return new String(get("getsourcesraw"));
        }
    }

    /**
     * Gets the file that corresponds with the given hash as a byte array from
     * MalShare
     *
     * @param hash the MD-5/SHA-1/SHA-256 hash of the file to dowlnoad
     * @return the requested sample as a byte array
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public byte[] getFile(String hash) throws IOException {
        return get("getfile&hash=" + hash);
    }

    /**
     * Gets the details of the stored filed that corresponds to the given hash
     *
     * Note that the JSON format is still returned in a String object. This is
     * done to allow the user of this library to use whatever JSON parser is
     * already in use, instead of using two different ones.
     *
     * @param hash the MD-5/SHA-1/SHA-256 hash of the file to obtain the details
     * from
     * @return the details of the requested hash in JSON format
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public String getFileDetailsJson(String hash) throws IOException {
        return new String(get("details&hash=" + hash));
    }

    /**
     * List MD-5/SHA-1/SHA-256 hashes of a specific type from the past 24 hours
     * in JSON format
     *
     * Note that the JSON format is still returned in a String object. This is
     * done to allow the user of this library to use whatever JSON parser is
     * already in use, instead of using two different ones.
     *
     * @param type the file type to look for from
     * @return the MD-5/SHA-1/SHA-256 hashes of the of the requested type in
     * JSON format
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public String getRecentFileTypesJson(String type) throws IOException {
        return new String(get("type&type=" + type));
    }

    /**
     * List MD5/SHA1/SHA256 hashes of a specific type from the past 24 hours in
     * JSON format
     *
     * Note that the JSON format is still returned in a String object. This is
     * done to allow the user of this library to use whatever JSON parser is
     * already in use, instead of using two different ones.
     *
     * @param query the query to search for
     * @return the details of the requested hash in JSON format
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public String searchJson(String query) throws IOException {
        return new String(get("search&query=" + query));
    }

    /**
     * Get list of file types and count from the past 24 hours in JSON format
     *
     * Note that the JSON format is still returned in a String object. This is
     * done to allow the user of this library to use whatever JSON parser is
     * already in use, instead of using two different ones.
     *
     * @return the MD-5/SHA-1/SHA-256 hashes of the of the requested type in
     * JSON format
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public String getRecentTypesJson() throws IOException {
        return new String(get("gettypes"));
    }

    /**
     * Get the allocated number of available API key requests per day and amount
     * of remaining API key requests
     *
     * Note that the JSON format is still returned in a String object. This is
     * done to allow the user of this library to use whatever JSON parser is
     * already in use, instead of using two different ones.
     *
     * @return the amount of total and the amount of available API key calls in
     * JSON format
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public String getApiKeyLimitJson() throws IOException {
        return new String(get("getlimit"));
    }

    /**
     * Check status of download task via GUID. Response contains one of the
     * following status values: missing, pending, processing, or finished. The
     * result is in JSON format.
     *
     * Note that the JSON format is still returned in a String object. This is
     * done to allow the user of this library to use whatever JSON parser is
     * already in use, instead of using two different ones.
     *
     * @param guid the GUID to check the status for
     * @return the download task status in JSON format
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public String getDownloadTaskStatusJson(String guid) throws IOException {
        return new String(get("download_url_check&guid=" + guid));
    }

    /**
     * Upload using FormData field "upload". Uploading files temporarily
     * increases a users quota.
     *
     * @param file the file object pointing to the sample to upload
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public void upload(File file) throws IOException {
        //Create a builder object
        MultipartEntityBuilder builder = MultipartEntityBuilder.create();
        //Add the upload field in plain text
        builder.addTextBody("upload", file.getName(), ContentType.TEXT_PLAIN);

        //Add the file itself
        builder.addBinaryBody(
                "file",
                new FileInputStream(file),
                ContentType.APPLICATION_OCTET_STREAM,
                file.getName()
        );
        //Execute the HTTP post request
        post("upload", builder);
    }

    /**
     * Download the sample from a URL and add it to MalShare's collection. The
     * target URL can be crawled recursively if the boolean is set to true.
     *
     * Note that the JSON format is still returned in a String object. This is
     * done to allow the user of this library to use whatever JSON parser is
     * already in use, instead of using two different ones.
     *
     * @param url the URL to download the sample from
     * @param recursive true if the URL should be crawled recursively, false if
     * not
     * @return the task's GUID
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public String addDownloadUrl(String url, boolean recursive) throws IOException {
        //Create the builder
        MultipartEntityBuilder builder = MultipartEntityBuilder.create();
        //Add the URL
        builder.addTextBody("url", url, ContentType.TEXT_PLAIN);

        //Set the value of recursive to 0, which needs to be a string to add it as a part of the body's form data
        String recursiveValue = "0";
        //If the recursive boolean is set, the value should change, otherwise it should stay as it is
        if (recursive) {
            recursiveValue = "1";
        }
        //Add the recursive value
        builder.addTextBody("recursive", recursiveValue, ContentType.TEXT_PLAIN);
        //Return the HTTP POST's response as a string
        return new String(post("download_url", builder));
    }
}
