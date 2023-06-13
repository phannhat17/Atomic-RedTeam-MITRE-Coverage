package hust.cybersec.data.collector;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.zip.GZIPInputStream;

import javax.net.ssl.*;

public class DataRetriever
{
	private String dataURL;
	private String directoryPath;
	private String[] filesPath;

	public DataRetriever(String dataURL, String directoryPath, String[] filesPath)
	{
		this.dataURL = dataURL;
		this.directoryPath = directoryPath;
		this.filesPath = filesPath;
	}

	public void download() throws URISyntaxException
	{
		download("");
	}

	public void download(String fileName) throws URISyntaxException
	{
		File directory = new File(directoryPath);

		// Create the directory if it doesn't exist
		if (!directory.exists())
		{
			directory.mkdirs();
		}
		Path directoryPathObj = Paths.get(directoryPath);

		for (String path : filesPath)
		{
			String finalFileName = fileName;
			try
			{
				if (fileName.isEmpty())
				{
					finalFileName = path.substring(path.lastIndexOf('/') + 1);
				}
				Path filePathObj = directoryPathObj.resolve(finalFileName);
				downloadUsingNIO(dataURL + path, filePathObj.toString());
			} catch (IOException e)
			{
				e.printStackTrace();
			}
		}

	};

	// Downloads a file using NIO (non-blocking I/O)
	protected void downloadUsingNIO(String urlStr, String file) throws IOException, URISyntaxException
	{
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
		try
		{
			httpsConnection.connect();
			validateCertificate(httpsConnection);
		} catch (SSLException e)
		{
			e.printStackTrace();
			return;
		}

		// Open a readable byte channel for the URL stream
		try (InputStream inputStream = new GZIPInputStream(httpsConnection.getInputStream());
				FileOutputStream fileOutputStream = new FileOutputStream(file))
		{
			byte[] buffer = new byte[8192];
			int bytesRead;
			while ((bytesRead = inputStream.read(buffer)) != -1)
			{
				fileOutputStream.write(buffer, 0, bytesRead);
			}
		} catch (IOException e)
		{
			e.printStackTrace();
		} finally
		{
			httpsConnection.disconnect();
		}

		long stop = System.currentTimeMillis();
		System.out.println("Run time: " + (stop - start));
	}

	private void validateCertificate(HttpsURLConnection connection) throws SSLException
	{
		try
		{
			// Implement additional validation logic if required
			// Verify certificate chain, expiration, revocation, etc.
			connection.getServerCertificates();
		} catch (SSLPeerUnverifiedException e)
		{
			throw new SSLException("Certificate verification failed", e);
		}
	}
}
