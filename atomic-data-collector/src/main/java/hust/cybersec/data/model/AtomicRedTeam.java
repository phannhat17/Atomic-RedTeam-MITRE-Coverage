package hust.cybersec.data.model;

import java.io.*;
import java.net.URISyntaxException;

import com.fasterxml.jackson.annotation.*;

import hust.cybersec.data.collector.DataRetriever;
import hust.cybersec.data.process.YamlToJsonConverter;
import hust.cybersec.functional.CoverageAnalyser;
import hust.cybersec.functional.ExcelExporter;

public class AtomicRedTeam extends MitreAttackFramework
{
	private int testNumber;

	@JsonProperty("name")
	private String testName;

	@JsonProperty("auto_generated_guid")
	private String testGuid;

	@JsonProperty("description")
	private String testDescription;

	@JsonProperty("supported_platforms")
	private String[] testSupportedPlatforms;

	@JsonProperty("input_arguments")
	private String[] testInputArguments;

	@JsonProperty("executor")
	private String[] testExecutor;

	@JsonProperty("dependency_executor_name")
	private String testDependencyExecutorName;

	@JsonProperty("dependencies")
	private String[] testDependencies;

	public AtomicRedTeam()
	{
		super();
	}

	public AtomicRedTeam(String testName, String testGuid, String testDescription, String[] testSupportedPlatforms,
			String[] testInputArguments, String[] testExecutor, String testDependencyExecutorName,
			String[] testDependencies)
	{
		super();
		this.testName = testName;
		this.testGuid = testGuid;
		this.testDescription = testDescription;
		this.testSupportedPlatforms = testSupportedPlatforms;
		this.testInputArguments = testInputArguments;
		this.testExecutor = testExecutor;
		this.testDependencyExecutorName = testDependencyExecutorName;
		this.testDependencies = testDependencies;
	}

	public AtomicRedTeam(int testNumber, String testName, String testGuid, String testDescription,
			String[] testSupportedPlatforms, String[] testInputArguments, String[] testExecutor,
			String testDependencyExecutorName, String[] testDependencies)
	{
		super();
		this.testNumber = testNumber;
		this.testName = testName;
		this.testGuid = testGuid;
		this.testDescription = testDescription;
		this.testSupportedPlatforms = testSupportedPlatforms;
		this.testInputArguments = testInputArguments;
		this.testExecutor = testExecutor;
		this.testDependencyExecutorName = testDependencyExecutorName;
		this.testDependencies = testDependencies;
	}

	public void setTestNumber(int testNumber)
	{
		this.testNumber = testNumber;
	}

	public int getTestNumber()
	{
		return testNumber;
	}

	public String getTestName()
	{
		return testName;
	}

	public String getTestGuid()
	{
		return testGuid;
	}

	public String getTestDescription()
	{
		return testDescription;
	}

	public String[] getTestSupportedPlatforms()
	{
		return testSupportedPlatforms;
	}

	public String[] getTestInputArguments()
	{
		return testInputArguments;
	}

	public String[] getTestExecutor()
	{
		return testExecutor;
	}

	public String getTestDependencyExecutorName()
	{
		return testDependencyExecutorName;
	}

	public String[] getTestDependencies()
	{
		return testDependencies;
	}

	public void downloadData() throws URISyntaxException
	{
		String atomicURL = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/";
		String atomicDirectory = "./data/atomic";
		String[] atomicFiles = { "index.yaml" };

		DataRetriever atomicDownloader = new DataRetriever(atomicURL, atomicDirectory, atomicFiles);
		atomicDownloader.download("atomic-all.yaml");

		String yamlFilePath = "./data/atomic/atomic-all.yaml";
		String jsonFilePath = "./data/atomic/atomic-all.json";

		YamlToJsonConverter converter = new YamlToJsonConverter(yamlFilePath, jsonFilePath);
		converter.convert();
	}

	public void exportExcel() throws FileNotFoundException, IOException
	{
		String jsonFilePath = "./data/atomic/atomic-all.json";
		String excelFilePath = "./data/atomic/atomic-all.xlsx";
		ExcelExporter exporter = new ExcelExporter(jsonFilePath, excelFilePath);
		exporter.export();
	}

	public int getNumTechniques(String taxonomy, String type)
	{
		return 0;
	}

	public void analyseCoverage(MitreAttackFramework mitre)
	{
		CoverageAnalyser analyser = new CoverageAnalyser(this, mitre);
		analyser.analyse();
	}

	public static void main(String[] args) throws URISyntaxException
	{
		AtomicRedTeam atomic = new AtomicRedTeam();
		// atomic.downloadData();
		try
		{
			atomic.exportExcel();
		} catch (IOException e)
		{
			e.printStackTrace();
		}
	}
}
