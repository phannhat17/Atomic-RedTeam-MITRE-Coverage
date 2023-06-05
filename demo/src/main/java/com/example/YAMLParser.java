package com.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;

import java.io.File;
import java.io.IOException;
import java.util.Map;

public class YAMLParser {
    public static void main(String[] args) {
        // Specify the path to your YAML file
        String filePath = "./atomic/collection/collection.yaml";

        // Create a YAMLMapper instance
        YAMLMapper mapper = new YAMLMapper(new YAMLFactory());

        try {
            // Parse the YAML file into a Map
            Map<String, Object> yamlData = mapper.readValue(new File(filePath), Map.class);

            // Process the parsed YAML data as needed
            // For example, you can access specific values using keys
            Object value = yamlData.get("key");

            System.out.println("Parsed YAML value: " + value);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
