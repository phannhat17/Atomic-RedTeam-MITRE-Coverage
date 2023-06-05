package com.example;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;

public class GetMITREData {

    public static void main(String[] args) {
        String downloadPath = "./mitre-attack";
        File directory = new File(downloadPath);
        if (!directory.exists()) {
            directory.mkdirs();
        }
        String downloadUrl = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/";
        String[] filesPath = { 
                "enterprise-attack/enterprise-attack.json", 
                "mobile-attack/mobile-attack.json",
                "ics-attack/ics-attack.json" 
            };
        for (String path : filesPath) {
            try {
                String fileName = path.substring(path.lastIndexOf('/') + 1);
                downloadUsingNIO(downloadUrl + path, downloadPath + "/" + fileName);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private static void downloadUsingNIO(String urlStr, String file) throws IOException {
        long start = System.currentTimeMillis();
        URL url = new URL(urlStr);
        ReadableByteChannel rbc = Channels.newChannel(url.openStream());
        FileOutputStream fos = new FileOutputStream(file);
        fos.getChannel().transferFrom(rbc, 0, Long.MAX_VALUE);
        fos.close();
        rbc.close();
        long stop = System.currentTimeMillis();
        System.out.println("Run time: " + (stop - start));
    }

}
