package com.example;

import java.io.*;
import java.net.*;
import java.nio.channels.*;

public class GetAtomic 
{

    public static void main(String[] args) throws URISyntaxException 
    {
        String downloadPath = "demo/data/atomic";
        File directory = new File(downloadPath);
        if (!directory.exists()) 
        {
            directory.mkdirs();
        }
        String downloadUrl = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/index.yaml";
        
        try 
        {
        	downloadUsingNIO(downloadUrl, downloadPath + "/atomic-all.yaml");
        } 
        catch (IOException e) 
        {
        	e.printStackTrace();
        } 
    }

    private static void downloadUsingNIO(String urlStr, String file) throws IOException, URISyntaxException 
    {
        long start = System.currentTimeMillis();
        URL url = new URI(urlStr).toURL();
        ReadableByteChannel rbc = Channels.newChannel(url.openStream());
        FileOutputStream fos = new FileOutputStream(file);
        fos.getChannel().transferFrom(rbc, 0, Long.MAX_VALUE);
        fos.close();
        rbc.close();
        long stop = System.currentTimeMillis();
        System.out.println("Run time: " + (stop - start));
    }

}