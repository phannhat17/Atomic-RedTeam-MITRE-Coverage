package com.example;

import java.net.URISyntaxException;

public class AtomicRedTeam extends MitreAttackFramework
{
	
	public void downloadData() throws URISyntaxException 
	{
		String atomicURL = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/";
    	String atomicDirectory = "demo/data/atomic";
    	String[] atomicFiles = {"index.yaml"};
    	
    	DataRetriever atomicDownloader = new DataRetriever(atomicURL, atomicDirectory, atomicFiles);
    	atomicDownloader.download("atomic-all.yaml");
    	
    	String yamlFilePath = "demo/data/atomic/atomic-all.yaml";
        String jsonFilePath = "demo/data/atomic/atomic-all.json";

        YamlToJsonConverter converter = new YamlToJsonConverter(yamlFilePath, jsonFilePath);
        converter.convert();
	}
	
	public void exportExcel()
	{
		ExcelExporter exporter = new ExcelExporter();
		exporter.export();
	}
	
	public int getNumTechniques()
	{
		return 0;
	}
	
	public void analyseCoverage(MitreAttackFramework mitre)
	{
		CoverageAnalyser analyser = new CoverageAnalyser(this, mitre);
		analyser.generateChart();
	}
	
	public static void main(String[] args) throws URISyntaxException
	{
		AtomicRedTeam atomic = new AtomicRedTeam();
		atomic.downloadData();
	}
}
