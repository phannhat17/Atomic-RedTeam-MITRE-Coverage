package com.example;

import java.net.URISyntaxException;

public class MitreAttackFramework 
{

	public void downloadData() throws URISyntaxException
	{
		String mitreURL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/";
    	String mitreDirectory = "demo/data/mitre-attack";
    	// Array of files to download
    	String[] mitreFiles = {
                "enterprise-attack/enterprise-attack.json",
                "mobile-attack/mobile-attack.json",
                "ics-attack/ics-attack.json"
        };
    	
    	DataRetriever mitreDownloader = new DataRetriever(mitreURL, mitreDirectory, mitreFiles);
    	mitreDownloader.download();
	}
	
	public int getNumTechniques()
	{
		return 0;
	}
	
	public static void main(String[] args) throws URISyntaxException
	{
		MitreAttackFramework mitre = new MitreAttackFramework();
		mitre.downloadData();
	}
	
}
