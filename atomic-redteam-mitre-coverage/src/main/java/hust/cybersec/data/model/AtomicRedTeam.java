package hust.cybersec.data.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import hust.cybersec.data.collector.DataRetriever;
import hust.cybersec.data.process.YamlToJsonConverter;
import hust.cybersec.functional.ExcelExporter;
import hust.cybersec.screen.ChartScreen;

import java.io.IOException;
import java.net.URISyntaxException;

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

	@Override
	public void downloadData() throws URISyntaxException
	{
		String ATOMIC_URL = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/";
		String ATOMIC_DIRECTORY = "./data/atomic";
		String[] ATOMIC_FILES = { "index.yaml" };

		DataRetriever atomicDownloader = new DataRetriever(ATOMIC_URL, ATOMIC_DIRECTORY, ATOMIC_FILES);
		atomicDownloader.download("atomic-all.yaml");

		String YAML_FILE_PATH = "./data/atomic/atomic-all.yaml";
		String JSON_FILE_PATH = "./data/atomic/atomic-all.json";

		YamlToJsonConverter converter = new YamlToJsonConverter(YAML_FILE_PATH, JSON_FILE_PATH);
		converter.convert();
	}

	public void exportExcel() throws IOException
	{
		String JSON_FILE_PATH = "./data/atomic/atomic-all.json";
		String EXCEL_FILE_PATH = "./data/atomic/atomic-all.xlsx";
		ExcelExporter exporter = new ExcelExporter(JSON_FILE_PATH, EXCEL_FILE_PATH);
		exporter.export();
	}

	public void analyseCoverage()
	{
		ChartScreen.LaunchScene();
	}
}
