package hust.cybersec;

import java.io.*;
import java.nio.file.*;
import org.yaml.snakeyaml.LoaderOptions;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.dataformat.yaml.*;

public class YamlToJsonConverter
{
	private final String yamlFilePath;
	private final String jsonFilePath;
	private final ObjectMapper yamlObjectMapper;
	private final ObjectMapper jsonObjectMapper;

	public YamlToJsonConverter(String yamlFilePath, String jsonFilePath)
	{
		this.yamlFilePath = yamlFilePath;
		this.jsonFilePath = jsonFilePath;

		LoaderOptions loaderOptions = new LoaderOptions();
		// Increase file size limitation to 10MB
		loaderOptions.setCodePointLimit(10 * 1024 * 1024);
		YAMLFactory yamlFactory = YAMLFactory.builder().loaderOptions(loaderOptions).build();
		this.yamlObjectMapper = new ObjectMapper(yamlFactory);
		this.jsonObjectMapper = new ObjectMapper();
	}

	public void convert()
	{
		long start = System.currentTimeMillis();

		try
		{
			byte[] yamlBytes = readYamlFile();
			Object json = convertYamlToJson(yamlBytes);
			writeJsonToFile(json);
		} catch (IOException e)
		{
			System.err.println("An error occurred during YAML to JSON conversion.");
			e.printStackTrace();
		}

		long stop = System.currentTimeMillis();
		System.out.println("Run time: " + (stop - start));
	}

	private byte[] readYamlFile() throws IOException
	{
		try
		{
			Path file = Path.of(yamlFilePath).normalize();
			if (!Files.isRegularFile(file))
			{
				throw new FileNotFoundException("The YAML file does not exist.");
			}
			return Files.readAllBytes(file);
		} catch (SecurityException e)
		{
			System.err.println("Insufficient permissions to read the YAML file.");
			throw e;
		} catch (IOException e)
		{
			System.err.println("An I/O error occurred while reading the YAML file.");
			throw e;
		}
	}

	private Object convertYamlToJson(byte[] yamlBytes)
	{
		try
		{
			return yamlObjectMapper.readValue(yamlBytes, Object.class);
		} catch (IOException ex)
		{
			System.err.println("Error occurred while converting YAML to JSON.");
			ex.printStackTrace();
		}
		return null;
	}

	private void writeJsonToFile(Object json) throws IOException
	{
		try (OutputStream outputStream = new FileOutputStream(jsonFilePath);
				BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(outputStream))
		{
			jsonObjectMapper.writerWithDefaultPrettyPrinter().writeValue(bufferedOutputStream, json);
		}
	}
}
