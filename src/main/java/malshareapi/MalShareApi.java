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
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * The MalShare malware dataset is accessible via an API. To avoid recreating a
 * handler for this API by several people, one can use this class.<br>
 * <br>
 * To compile this library as a single library that contains all dependencies,
 * use:<br>
 * <br>
 * <code>mvn clean compile assembly:single</code><br>
 * <br>
 * To generate the files that one requires for a Maven installation (including
 * Javadoc), use:<br>
 * <br>
 * <code>mvn package</code>
 *
 * @author Max 'Libra' Kersten [@Libranalysis, https://maxkersten.nl]
 */
public class MalShareApi {

    /**
     * The object to send HTTP requests to the MalShare back-end, which returns
     * the server's response
     */
    private MalShareConnector connector;

    /**
     * To interact with the API, a valid API key is required. All API endpoints
     * are covered by the public functions in this class. To minimise the needed
     * dependencies, JSON responses are returned in the form of a string. Files
     * are returned as byte arrays.<br>
     * <br>
     * The IOException that is possibly thrown by any API call contains a useful
     * error message for the user.
     *
     * @param apiKey a valid MalShare API key
     */
    public MalShareApi(String apiKey) {
        //Set the API base
        String apiBase = "https://malshare.com/api.php?api_key=" + apiKey + "&action=";
        //Initialise the connector
        this.connector = new MalShareConnector(apiBase);
    }

    /**
     * Returns a boxed byte array based on the given native byte array. The
     * reason that a boxed array is required, is that native types cannot be
     * used in lists, mappings, nor sets.
     *
     * @param input the byte array to convert into a boxed byte array
     * @return a boxed bye array with the same values as the input array
     */
    private Byte[] box(byte[] input) {
        //Creates a boxed byte array, which is required in the mapping
        Byte[] output = new Byte[input.length];

        //Box all values
        for (int i = 0; i < input.length; i++) {
            output[i] = input[i];
        }

        return output;
    }

    /**
     * This function returns all hashes that were added to MalShare in the last
     * 24 hours. This list is created once a day by MalShare's back-end, meaning
     * won't change until the next day. It is <b>not</b> looking back 24 hours
     * in time from the moment this function is called.<br>
     * <br>
     * This function returns the hashes as a list of
     * <code>MalShareHashObject</code> objects. Each of these objects contains
     * the MD-5, SHA-1, and SHA-256 hash of the same sample.
     *
     * @return a list of hashes of the last 24 hours, in several hashing formats
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public List<MalShareHashObject> getList() throws IOException {
        List<MalShareHashObject> result = new ArrayList<>();

        String response = new String(connector.get("getlistraw"));
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
     * Gets a list of sample sources from the past 24 hours in plain text. This
     * list is made once a day by MalShare, meaning it does <b>not</b> matter
     * when this function is called.
     *
     * @return a list of sources, one entry per string in the list
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public List<String> getSources() throws IOException {
        List<String> sources = new ArrayList<>();

        String response = new String(connector.get("getsourcesraw"));
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
     * @throws IOException if an exception occurs when making the request, or if
     * a sample does not exist on MalShare. The exception will be thrown with a
     * relevant error message
     */
    public byte[] getFile(String hash) throws IOException {
        byte[] response = connector.get("getfile&hash=" + hash);
        return response;
    }

    /**
     * Returns a mapping of all available samples, with the provided hash as the
     * key, and the raw sample as a value.
     *
     * @param hashes the hashes to download
     * @param suppressExceptions when true, suppresses exceptions from samples
     * that are not in MalShare's dataset. When set to false, the error is
     * thrown. This does mean that a single missing sample in the given list,
     * will result in an error thrown by this function, and the loss of all
     * already downloaded samples.
     * @return a mapping with all available samples
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public Map<String, Byte[]> getFiles(List<String> hashes, boolean suppressExceptions) throws IOException {
        Map<String, Byte[]> mapping = new HashMap<>();

        for (String hash : hashes) {
            try {
                Byte[] sample = box(getFile(hash));
                mapping.put(hash, sample);
            } catch (IOException ex) {
                //If the function should surpress faulty samples, the error is ignored
                if (suppressExceptions == false) {
                    throw ex;
                }
            }
        }

        return mapping;
    }

    /**
     * Gets the details of the stored files that correspond with the given hash
     *
     * @param hash the MD-5/SHA-1/SHA-256 hash of the file to obtain the details
     * from
     * @return the details of the requested hash in a
     * <code>MalShareFileDetails</code> object.
     * @throws IOException if an exception occurs when making the request, or if
     * the hash is not known in MalShare's dataset. The exception will be thrown
     * with a relevant error message
     */
    public MalShareFileDetails getFileDetails(String hash) throws IOException {
        JSONObject response = new JSONObject(new String(connector.get("details&hash=" + hash)));

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
     * A list of MD-5/SHA-1/SHA-256 hashes of all samples that match the
     * specific type, from the past 24 hours. If no matches are found for the
     * given type, the returned list is empty.
     *
     * @param type the file type to look for
     * @return the MD-5/SHA-1/SHA-256 hashes of the of the requested type
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public List<MalShareHashObject> getRecentFileTypes(String type) throws IOException {
        List<MalShareHashObject> results = new ArrayList<>();

        JSONArray json = new JSONArray(new String(connector.get("type&type=" + type)));

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
     * The search results for the given query, one entry per item in the
     * returned list. If no results are found, the returned list is empty.
     *
     * @param query the query to search for
     * @return the search results
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public List<MalShareSearchResult> search(String query) throws IOException {
        List<MalShareSearchResult> results = new ArrayList<>();

        query = URLEncoder.encode(query, StandardCharsets.UTF_8.toString());

        JSONArray json = new JSONArray(new String(connector.get("search&query=" + query)));

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
     * Gets a list of file types and count from the past 24 hours in a mapping.
     * The list of types is made once a day by MalShare, meaning it does
     * <b>not</b> matter at what time you make this request, as it does not work
     * retroactively based on the time the server receives the request.<br>
     * <br>
     * The mapping's keys are the type names, whereas the value for each key is
     * the amount of occurrences.
     *
     * @return the recently used types and the frequency in which they occurred,
     * in a mapping
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public Map<String, Integer> getRecentTypes() throws IOException {
        Map<String, Integer> mapping = new HashMap<>();
        JSONObject json = new JSONObject(new String(connector.get("gettypes")));

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
     * @return the amount of total and the amount of available API key calls in
     * a MalShareApiLimit object
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public MalShareApiLimit getApiKeyLimit() throws IOException {
        JSONObject jsonObject = new JSONObject(new String(connector.get("getlimit")));
        int limit = jsonObject.optInt("LIMIT");
        int remaining = jsonObject.optInt("REMAINING");
        return new MalShareApiLimit(limit, remaining);
    }

    /**
     * Checks the status of the download task for a given GUID. The response
     * contains one of the following status values: missing, pending,
     * processing, or finished.<br>
     * <br>
     * The status of the given GUID is returned as a string. In version
     * 1.0-stable of this API, the raw JSON was returned.
     *
     * @param guid the GUID to check the status for
     * @return the download task status, or an empty string if the GUID is
     * invalid
     * @throws IOException if an exception occurs when making the request, or if
     * the given GUID is unknown. The exception will be thrown with a relevant
     * error message
     */
    public String getDownloadTaskStatus(String guid) throws IOException {
        JSONObject json = new JSONObject(new String(connector.get("download_url_check&guid=" + guid)));
        return json.optString("status");
    }

    /**
     * Checks the status of the download task for a given list of GUIDs. The
     * status is one of the following status values: missing, pending,
     * processing, or finished.
     *
     * @param guids the GUIDs to check for
     * @param suppressExceptions true if exceptions need to be suppressed, false
     * if any exception should be thrown
     * @return a mapping where the keys are the provided GUIDs, and the value
     * for each key is its status
     * @throws IOException if an exception occurs when making the request, or if
     * the given GUID is unknown. The exception will be thrown with a relevant
     * error message
     */
    public Map<String, String> getDownloadTaskStatuses(List<String> guids, boolean suppressExceptions) throws IOException {
        Map<String, String> mapping = new HashMap<>();

        for (String guid : guids) {
            try {
                String status = getDownloadTaskStatus(guid);
                mapping.put(guid, status);
            } catch (IOException ex) {
                if (suppressExceptions == false) {
                    throw ex;
                }
            }
        }

        return mapping;
    }

    /**
     * Upload a file using the FormData field "upload". Uploading files
     * temporarily increases a user's quota.<br>
     * <br>
     * Note that the file has to exist, or an IOException will be thrown. If the
     * file object points to a folder, all files within that folder will
     * (non-recursively) be uploaded instead.
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
     * Upload multiple files using the FormData field "upload". Uploading files
     * temporarily increases a user's quota.<br>
     * <br>
     * Note that each file object has to point towards an existing file (not a
     * folder), or the entry in the list will be skipped!
     *
     * @param files the list of file objects pointing to samples to upload
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
        connector.post("upload", builder);
    }

    /**
     * Download the sample from a URL and add it to MalShare's collection. The
     * target URL can be crawled recursively if the boolean is set to true.<br>
     * <br>
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
        JSONObject json = new JSONObject(new String(connector.post("download_url", builder)));
        return json.optString("guid");
    }

    /**
     * Download samples from a given list of URLs and add them to MalShare's
     * collection. The target URLs can be crawled recursively if the boolean is
     * set to true.<br>
     * <br>
     * Only the GUID is returned. In version 1.0-stable of this library, the raw
     * JSON format was returned.
     *
     * @param urls the URLs to download the samples from
     * @param recursive true if all URLs in the given list should be crawled
     * recursively, false if not
     * @return A mapping where the keys are the URLs, and the value for each key
     * is the returned GUID
     * @throws IOException if an exception occurs when making the request, the
     * exception will be thrown with a relevant error message
     */
    public Map<String, String> addDownloadUrls(List<String> urls, boolean recursive) throws IOException {
        Map<String, String> mapping = new HashMap<>();

        for (String url : urls) {
            String guid = addDownloadUrl(url, recursive);
            mapping.put(url, guid);
        }

        return mapping;
    }
}
