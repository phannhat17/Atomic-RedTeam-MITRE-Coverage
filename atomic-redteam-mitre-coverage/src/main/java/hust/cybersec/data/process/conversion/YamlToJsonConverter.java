package hust.cybersec.data.process.conversion;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.yaml.snakeyaml.LoaderOptions;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;

public class YamlToJsonConverter {
    private final String yamlFilePath;
    private final String jsonFilePath;
    private final ObjectMapper yamlObjectMapper;
    private final ObjectMapper jsonObjectMapper;

    /**
     * Create a new YamlToJsonConverter.
     *
     * @param yamlFilePath The path to the YAML file to convert
     * @param jsonFilePath The path to the JSON file to write
     */
    public YamlToJsonConverter(String yamlFilePath, String jsonFilePath) {
        this.yamlFilePath = yamlFilePath;
        this.jsonFilePath = jsonFilePath;

        LoaderOptions loaderOptions = new LoaderOptions();
        // Increase file size limitation to 10MB
        loaderOptions.setCodePointLimit(10 * 1024 * 1024);
        YAMLFactory yamlFactory = YAMLFactory.builder().loaderOptions(loaderOptions).build();
        this.yamlObjectMapper = new ObjectMapper(yamlFactory);
        this.jsonObjectMapper = new ObjectMapper();
    }

    /**
     * Convert YAML file to JSON and write the result to a file.
     */
    public void convert() {
        System.out.println("Converting atomic-all.yaml to atomic-all.json");
        long start = System.currentTimeMillis();

        try {
            byte[] yamlBytes = readYamlFile();
            Object json = convertYamlToJson(yamlBytes);
            writeJsonToFile(json);
        } catch (IOException e) {
            System.err.println("An error occurred during YAML to JSON conversion.");
        }

        long stop = System.currentTimeMillis();
        System.out.println("Run time: " + (stop - start));
    }

    /**
     * Read the YAML file and return its contents as a byte array.
     *
     * @return The contents of the YAML file as a byte array
     * @throws IOException If an I/O error occurs while reading the file
     */
    private byte[] readYamlFile() throws IOException {
        try {
            Path file = Path.of(yamlFilePath).normalize();
            if (!Files.isRegularFile(file)) {
                throw new FileNotFoundException("The YAML file does not exist.");
            }
            return Files.readAllBytes(file);
        } catch (SecurityException e) {
            System.err.println("Insufficient permissions to read the YAML file.");
            throw e;
        } catch (IOException e) {
            System.err.println("An I/O error occurred while reading the YAML file.");
            throw e;
        }
    }

    /**
     * Convert the given YAML byte array to a JSON object.
     *
     * @param yamlBytes The YAML byte array to convert
     * @return The resulting JSON object
     */
    private Object convertYamlToJson(byte[] yamlBytes) {
        try {
            return yamlObjectMapper.readValue(yamlBytes, Object.class);
        } catch (IOException ex) {
            System.err.println("Error occurred while converting YAML to JSON.");
        }
        return null;
    }

    /**
     * Write the given JSON object to a file.
     *
     * @param json The JSON object to write
     * @throws IOException If an I/O error occurs while writing the file
     */
    private void writeJsonToFile(Object json) throws IOException {
        try (OutputStream outputStream = new FileOutputStream(jsonFilePath);
             BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(outputStream)) {
            jsonObjectMapper.writerWithDefaultPrettyPrinter().writeValue(bufferedOutputStream, json);
        }
    }
}
