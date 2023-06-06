package com.example;

import java.io.*;
import java.nio.file.*;

import org.yaml.snakeyaml.LoaderOptions;

import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.dataformat.yaml.*;
 
public class ConvertYAMLToJSON 
{
    public static void main(String[] args) 
    {
        String content = "";
        try
        {
            content = new String(Files.readAllBytes(Paths.get("demo/data/atomic/atomic-all.yaml")));
            
            //System.out.println("*********Content from YAML File ****************");
            //System.out.println(content);
            
            long start = System.currentTimeMillis();
            Object json = convertYamlToJson(content);
            
            //System.out.println("*********Converted JSON from YAML File ****************");
            //System.out.println(jsonString);
            
            try 
            {
            	ObjectMapper mapper = new ObjectMapper();
                mapper.writerWithDefaultPrettyPrinter().writeValue(new File("demo/data/atomic/atomic-all.json"), json);
            }
            catch (IOException e)
            {
            	e.printStackTrace();
            }
            
            long stop = System.currentTimeMillis();
            System.out.println("Run time: " + (stop - start));
        } 
        catch (IOException e) 
        {
            e.printStackTrace();
        }
    }
 
    private static Object convertYamlToJson(String yaml) 
    {
        try 
        {
        	LoaderOptions loaderOptions = new LoaderOptions();
        	//Increase file size limitation to 10MB
        	loaderOptions.setCodePointLimit(10 * 1024 * 1024); 
        	YAMLFactory yamlFactory = YAMLFactory.builder().loaderOptions(loaderOptions).build();
            ObjectMapper yamlReader = new ObjectMapper(yamlFactory);
            Object obj = yamlReader.readValue(yaml, Object.class);
            return obj;
        } 
        catch (JsonProcessingException ex) 
        {
            ex.printStackTrace();
        } 
        
        return null;
    }
}