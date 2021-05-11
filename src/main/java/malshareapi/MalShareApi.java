/*
 * Copyright (C) 2020 Max 'Libra' Kersten [@Libranalysis, https://maxkersten.nl]
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
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * The MalShare malware dataset is accessible via an API. To avoid recreating a
 * handler for this API by several people, one can use this class.
 *
 * To complile this library as a single library that contains all dependencies:
 *
 * mvn clean compile assembly:single
 *
 * To generate the files that one requires for a Maven installation (including
 * Javadoc), use:
 *
 * mvn package
 *
 * @author Max 'Libra' Kersten [@Libranalysis, https://maxkersten.nl]
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
    @Deprecated
    public String getList(boolean json) throws IOException {
        if (json) {
            return new String(get("getlist"));
        } else {
            return new String(get("getlistraw"));
        }
    }

    /**
     * This function returns all hashes that were added to MalShare in the last
     * 24 hours. This function returns this value as a list of
     * MalShareHashObject objects. Each of these objects contain the MD-5,
     * SHA-1, and SHA-256 hash of the same sample.
     *
     * @return a list of hashes of the last 24 hours, in several hashing formats
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public List<MalShareHashObject> getList() throws IOException {
        List<MalShareHashObject> result = new ArrayList<>();

        String response = new String(get("getlistraw"));
        String[] array = response.split("\n");

        for (String hashEntry : array) {
            String[] hashes = hashEntry.split(" ");
            String md5 = hashes[0];
            String sha1 = hashes[1];
            String sha256 = hashes[2];
            result.add(new MalShareHashObject(md5, sha1, sha256));
        }

        return result;
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
     * @return a list of all sample sources in either JSON or plaintext format,
     * in the form of a String object
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    @Deprecated
    public String getSources(boolean json) throws IOException {
        if (json) {
            return new String(get("getsources"));
        } else {
            return new String(get("getsourcesraw"));
        }
    }

    /**
     * Gets a list of sample sources from the past 24 hours in plain text
     *
     * @return a list of sources, one entry per string in the list
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public List<String> getSources() throws IOException {
        List<String> sources = new ArrayList<>();

        String response = new String(get("getsourcesraw"));
        sources.addAll(Arrays.asList(response.split("\n")));

        return sources;
    }

    /**
     * Gets the file that corresponds with the given hash as a byte array from
     * MalShare
     *
     * @param hash the MD-5/SHA-1/SHA-256 hash of the file to download
     * @return the requested sample as a byte array, or an empty byte array if
     * the sample cannot be found
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public byte[] getFile(String hash) throws IOException {
        byte[] response = get("getfile&hash=" + hash);
        if (new String(response).contains("Sample not found by hash (")) {
            return new byte[0];
        }
        return response;
    }

    /**
     * Returns a mapping of all available samples, with the provided hash as the
     * key, and the raw sample as a value. Samples that were not found on
     * MalShare are not included in this mapping.
     *
     * @param hashes the hashes to download
     * @return a mapping with all available samples
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public Map<String, Byte[]> getFiles(List<String> hashes) throws IOException {
        Map<String, Byte[]> mapping = new HashMap<>();

        for (String hash : hashes) {
            MalShareFileDetails details = getFileDetails(hash);
            if (details.isEmpty()) {
                continue;
            }
            byte[] sampleRaw = getFile(hash);
            Byte[] sample = new Byte[sampleRaw.length];

            for (int i = 0; i < sampleRaw.length; i++) {
                sample[i] = sampleRaw[i];
            }

            mapping.put(hash, sample);
        }

        return mapping;
    }

    /**
     * Gets the details of the stored filed that corresponds with the given hash
     * in JSON format.
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
    @Deprecated
    public String getFileDetailsJson(String hash) throws IOException {
        return new String(get("details&hash=" + hash));
    }

    /**
     * Gets the details of the stored filed that corresponds with the given hash
     *
     * @param hash the MD-5/SHA-1/SHA-256 hash of the file to obtain the details
     * from
     * @return the details of the requested hash in a MalShareFileDetails
     * object. An empty object is returned if the sample cannot be found (see
     * the "isEmpty()" function within the MalShareFileDetails object)
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public MalShareFileDetails getFileDetails(String hash) throws IOException {
        JSONObject response = new JSONObject(new String(get("details&hash=" + hash)));

        String md5 = response.optString("MD5");
        String sha1 = response.optString("SHA1");
        String sha256 = response.optString("SHA256");
        MalShareHashObject hashObject = new MalShareHashObject(md5, sha1, sha256);

        String ssDeep = response.optString("SSDEEP");
        String fileType = response.optString("F_TYPE");

        JSONArray sourcesJson = response.optJSONArray("SOURCES");
        if (sourcesJson == null) {
            return new MalShareFileDetails();
        }
        List<String> sources = new ArrayList<>();

        for (int i = 0; i < sourcesJson.length(); i++) {
            String string = sourcesJson.optString(i);
            if (string.isEmpty() == false) {
                sources.add(string);
            }
        }

        return new MalShareFileDetails(hashObject, ssDeep, fileType, sources);
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
    @Deprecated
    public String getRecentFileTypesJson(String type) throws IOException {
        return new String(get("type&type=" + type));
    }

    /**
     * A list of MD-5/SHA-1/SHA-256 hashes of all samples that match the
     * specific type, from the past 24 hours
     *
     * @param type the file type to look for from
     * @return the MD-5/SHA-1/SHA-256 hashes of the of the requested type
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public List<MalShareHashObject> getRecentFileTypes(String type) throws IOException {
        List<MalShareHashObject> results = new ArrayList<>();

        JSONArray json = new JSONArray(new String(get("type&type=" + type)));

        for (int i = 0; i < json.length(); i++) {
            JSONObject object = json.optJSONObject(i);

            String md5 = object.optString("md5");
            String sha1 = object.optString("sha1");
            String sha256 = object.optString("sha256");
            results.add(new MalShareHashObject(md5, sha1, sha256));
        }

        return results;
    }

    /**
     * The search results in the form of a string in JSON format
     *
     * Note that the JSON format is still returned in a String object. This is
     * done to allow the user of this library to use whatever JSON parser is
     * already in use, instead of using two different ones.
     *
     * @param query the query to search for
     * @return the search results as a JSON string
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    @Deprecated
    public String searchJson(String query) throws IOException {
        return new String(get("search&query=" + URLEncoder.encode(query, StandardCharsets.UTF_8.toString())));
    }

    /**
     * The search results for the given query, one entry per item in the
     * returned list
     *
     * @param query the query to search for
     * @return the search results
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public List<MalShareSearchResult> search(String query) throws IOException {
        List<MalShareSearchResult> results = new ArrayList<>();

        query = URLEncoder.encode(query, StandardCharsets.UTF_8.toString());

        JSONArray json = new JSONArray(new String(get("search&query=" + query)));

        for (int i = 0; i < json.length(); i++) {
            JSONObject object = json.optJSONObject(i);
            String md5 = object.optString("md5");
            String sha1 = object.optString("sha1");
            String sha256 = object.optString("sha256");
            MalShareHashObject hashObject = new MalShareHashObject(md5, sha1, sha256);

            String type = object.optString("type");
            long epoch = object.optLong("added");
            LocalDateTime dateTime = LocalDateTime.ofInstant(Instant.ofEpochSecond(epoch), ZoneOffset.UTC);

            String source = object.optString("source");

            String yaraHits = object.optString("yarahits");
            if (yaraHits.equalsIgnoreCase("null")) {
                yaraHits = "";
            }

            List<String> parentFiles = new ArrayList<>();
            JSONArray parentFilesArray = object.optJSONArray("parentfiles");
            for (int j = 0; j < parentFilesArray.length(); j++) {
                String parentFile = parentFilesArray.optString(i);
                if (parentFile.isEmpty() == false) {
                    parentFiles.add(parentFile);
                }
            }

            List<String> subFiles = new ArrayList<>();
            JSONArray subFilesArray = object.optJSONArray("subfiles");
            for (int j = 0; j < subFilesArray.length(); j++) {
                String subFile = subFilesArray.optString(i);
                if (subFile.isEmpty() == false) {
                    subFiles.add(subFile);
                }
            }
            results.add(new MalShareSearchResult(hashObject, type, dateTime, source, yaraHits, parentFiles, subFiles));
        }

        return results;

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
    @Deprecated
    public String getRecentTypesJson() throws IOException {
        return new String(get("gettypes"));
    }

    /**
     * Get list of file types and count from the past 24 hours in a mapping. The
     * mapping's keys are the type names, whereas the value for each key is the
     * amount of occurrences.
     *
     * @return the recently used types and the frequency in which they occurred,
     * in a mapping
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public Map<String, Integer> getRecentTypes() throws IOException {
        Map<String, Integer> mapping = new HashMap<>();
        JSONObject json = new JSONObject(new String(get("gettypes")));

        Set<String> keySet = json.keySet();
        for (String key : keySet) {
            mapping.put(key, json.optInt(key));
        }
        return mapping;
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
    @Deprecated
    public String getApiKeyLimitJson() throws IOException {
        return new String(get("getlimit"));
    }

    /**
     * Get the allocated number of available API key requests per day and amount
     * of remaining API key requests
     *
     * @return the amount of total and the amount of available API key calls in
     * a MalShareApiLimit object
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public MalShareApiLimit getApiKeyLimit() throws IOException {
        JSONObject jsonObject = new JSONObject(new String(get("getlimit")));
        int limit = jsonObject.optInt("LIMIT");
        int remaining = jsonObject.optInt("REMAINING");
        return new MalShareApiLimit(limit, remaining);
    }

    /**
     * Check status of download task via GUID. Response contains one of the
     * following status values: missing, pending, processing, or finished. The
     * result is in JSON format.
     *
     * The raw JSON response is returned in a String object.
     *
     * @param guid the GUID to check the status for
     * @return the download task status in JSON format
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    @Deprecated
    public String getDownloadTaskStatusJson(String guid) throws IOException {
        return new String(get("download_url_check&guid=" + guid));
    }

    /**
     * Check status of download task via GUID. Response contains one of the
     * following status values: missing, pending, processing, or finished.
     *
     * The status of the given GUID is returned as a string. In version
     * 1.0-stable of this API, the raw JSON was returned.
     *
     * @param guid the GUID to check the status for
     * @return the download task status, or an empty string if the GUID is
     * invalid
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public String getDownloadTaskStatus(String guid) throws IOException {
        JSONObject json = new JSONObject(new String(get("download_url_check&guid=" + guid)));
        return json.optString("status");
    }

    /**
     * Upload a file using FormData field "upload". Uploading files temporarily
     * increases a users quota.
     *
     * Note that the file has to exist, or an IOException will be thrown. If the
     * file object points to a folder, all files within that folder
     * (non-recursive) will be uploaded instead.
     *
     * @param file the file object pointing to the sample to upload, which can
     * point to a file or a folder
     * @throws IOException if an exception occurs when making the request, or if
     * something is wrong with the given file object. The exception will be
     * thrown with a relevant error message
     */
    public void upload(File file) throws IOException {
        if (file.exists() == false) {
            throw new IOException("The given file does not exist!");
        } else if (file.isDirectory()) {
            List<File> files = new ArrayList<>();
            files.addAll(Arrays.asList(file.listFiles()));
            upload(files);
        } else if (file.isFile()) {
            uploadFile(file);
        }
    }

    /**
     * Upload multiple files using FormData field "upload". Uploading files
     * temporarily increases a users quota.
     *
     * Note that the file has to exist and has to be a file (not a folder), or
     * an IOException will be thrown.
     *
     * @param files the list of file object pointing to samples to upload
     * @throws IOException if an exception occurs when making the request, or if
     * something is wrong with the given file object. The exception will be
     * thrown with a relevant error message
     */
    public void upload(List<File> files) throws IOException {
        for (File file : files) {
            if (file.exists() && file.isFile()) {
                upload(file);
            }
        }
    }

    /**
     * Private function that contains the actual upload logic, without any
     * checks. It assumes the file object points to an existing file.
     *
     * @param file the existing file (not folder) to upload
     * @throws IOException if the request fails for any reason
     */
    private void uploadFile(File file) throws IOException {
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
     * Only the GUID is returned. In version 1.0-stable of this library, the raw
     * JSON format was returned.
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
        JSONObject json = new JSONObject(new String(post("download_url", builder)));
        return json.optString("guid");
    }
}
