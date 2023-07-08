package hust.cybersec.data.collector;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocketFactory;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.zip.GZIPInputStream;

public class DataRetriever {
    private final String dataURL;
    private final String directoryPath;
    private final String[] filesPath;

    /**
     * Constructs a DataRetriever object with the specified data URL, directory path, and file paths.
     *
     * @param dataURL       The URL for the data.
     * @param directoryPath The path where the files will be saved.
     * @param filesPath     An array of file paths to download.
     */
    public DataRetriever(String dataURL, String directoryPath, String[] filesPath) {
        this.dataURL = dataURL;
        this.directoryPath = directoryPath;
        this.filesPath = filesPath;
    }

    /**
     * Downloads a files specified by filesPath into the directoryPath.
     *
     * @throws URISyntaxException If the URL syntax is invalid.
     */
    public void download() throws URISyntaxException {
        download("");
    }

    /**
     * Downloads a specific file specified by fileName into the directoryPath.
     *
     * @param fileName The name of the file to be downloaded.
     * @throws URISyntaxException If the URL syntax is invalid.
     */
    public void download(String fileName) throws URISyntaxException {
        File directory = new File(directoryPath);

        // Create the directory if it doesn't exist
        if (!directory.exists()) {
            directory.mkdirs();
        }
        Path directoryPathObj = Paths.get(directoryPath);

        for (String path : filesPath) {
            String finalFileName = fileName;
            try {
                if (fileName.isEmpty()) {
                    finalFileName = path.substring(path.lastIndexOf('/') + 1);
                }
                Path filePathObj = directoryPathObj.resolve(finalFileName);
                downloadUsingNIO(dataURL + path, filePathObj.toString());
            } catch (IOException e) {
                System.out.println(e.getMessage());
            }
        }
    }

    /**
     * Downloads a file using NIO (non-blocking I/O) from the given URL and saves it to the specified file path.
     *
     * @param urlStr The URL of the file to download.
     * @param file   The path where the file will be saved.
     * @throws IOException        If an I/O error occurs during the download.
     * @throws URISyntaxException If the URL syntax is invalid.
     */
    protected void downloadUsingNIO(String urlStr, String file) throws IOException, URISyntaxException {

        System.out.println("Downloading " + file);

        long start = System.currentTimeMillis();

        // Create a URL object from the provided URL string
        URL url = new URI(urlStr).toURL();

        // Set up SSL/TLS security
        HttpsURLConnection httpsConnection = (HttpsURLConnection) url.openConnection();
        httpsConnection.setSSLSocketFactory((SSLSocketFactory) SSLSocketFactory.getDefault());
        httpsConnection.setHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier());

        // Enable gzip compression
        httpsConnection.setRequestProperty("Accept-Encoding", "gzip");

        // Check the server's certificate chain validity
        try {
            httpsConnection.connect();
            validateCertificate(httpsConnection);
        } catch (SSLException e) {
            System.out.println(e.getMessage());
            return;
        }

        // Open a readable byte channel for the URL stream
        try (InputStream inputStream = new GZIPInputStream(httpsConnection.getInputStream());
             FileOutputStream fileOutputStream = new FileOutputStream(file)) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                fileOutputStream.write(buffer, 0, bytesRead);
            }
        } catch (IOException e) {
            System.out.println(e.getMessage());
        } finally {
            httpsConnection.disconnect();
        }

        long stop = System.currentTimeMillis();
        System.out.println("Run time: " + (stop - start));
    }

    /**
     * Validates the server's certificate chain.
     *
     * @param connection The HTTPS connection used to download the file.
     * @throws SSLException If the certificate verification fails.
     */
    private void validateCertificate(HttpsURLConnection connection) throws SSLException {
        try {
            // Implement additional validation logic if required
            // Verify certificate chain, expiration, revocation, etc.
            connection.getServerCertificates();
        } catch (SSLPeerUnverifiedException e) {
            throw new SSLException("Certificate verification failed", e);
        }
    }
}