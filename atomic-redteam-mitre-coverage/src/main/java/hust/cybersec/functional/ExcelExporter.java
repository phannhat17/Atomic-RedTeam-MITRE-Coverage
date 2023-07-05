package hust.cybersec.functional;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import hust.cybersec.data.model.AtomicRedTeam;
import hust.cybersec.data.model.MitreAttackFramework;
import hust.cybersec.data.process.JsonNodeHandler;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.ss.usermodel.Font;
import org.apache.poi.ss.util.CellRangeAddress;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import java.awt.*;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

public class ExcelExporter
{
	private static final String[] HEADERS = { "No.", "Technique ID", "Technique Name", "Technique Description",
			"Technique Platforms", "Technique Domains", "Technique URL", "Technique Tactics", "Technique Detection",
			"Is Subtechnique", "Test #", "Test Name", "Test GUID", "Test Description", "Test Supported Platforms",
			"Test Input Arguments", "Test Executor", "Test Dependency Executor Name", "Test Dependencies" };
	private final String jsonFilePath;
	private final String excelFilePath;

	private final JsonNodeHandler jsonHandler = new JsonNodeHandler();

	public ExcelExporter(String jsonFilePath, String excelFilePath)
	{
		this.jsonFilePath = jsonFilePath;
		this.excelFilePath = excelFilePath;
	}

	public void export() throws IOException
	{
		long start = System.currentTimeMillis();

		String jsonData = new String(Files.readAllBytes(Paths.get(jsonFilePath)));
		List<AtomicRedTeam> atomicTests = mapJsonToAtomicTests(jsonData);

		Workbook workbook = new XSSFWorkbook();
		Sheet sheet = workbook.createSheet("Atomic Test");
		sheet.setZoom(50);

		createTitleRow(sheet);

		Row spaceRow = sheet.createRow(1);
		sheet.addMergedRegion(new CellRangeAddress(1, 1, 0, 18));
		spaceRow.setHeightInPoints((short) 50);

		createHeaderRow(sheet);
		createSubHeaderRow(sheet);

		createDataRows(sheet, atomicTests);
		autoSizeColumns(sheet);
		hideTechniqueColumns(sheet);

		applyFilter(sheet);

		writeWorkbook(workbook);
		System.out.println("Excel file exported successfully to " + excelFilePath);

		openFile(excelFilePath);

		long stop = System.currentTimeMillis();
		System.out.println("Run time: " + (stop - start));
	}

	private List<AtomicRedTeam> mapJsonToAtomicTests(String jsonData) throws IOException
	{
		HashSet<String> testID = new HashSet<>();
		ObjectMapper objectMapper = new ObjectMapper();
		JsonNode root = objectMapper.readTree(jsonData);
		List<AtomicRedTeam> atomicTests = new ArrayList<>();

		for (JsonNode tacticList : root)
		{
			for (JsonNode list : tacticList)
			{
				JsonNode techniqueNode = list.get("technique");
				JsonNode atomicTestsNode = list.get("atomic_tests");
				if (!jsonHandler.checkValid(techniqueNode))
				{
					continue;
				}
				if (atomicTestsNode != null && atomicTestsNode.isArray() && !atomicTestsNode.isEmpty())
				{
					MitreAttackFramework technique = objectMapper.treeToValue(techniqueNode,
							MitreAttackFramework.class);
					int testNumber = 0;
					for (JsonNode atomicTestNode : atomicTestsNode)
					{
						if (!atomicTestNode.has("auto_generated_guid"))
						{
							continue;
						}
						String testAutoID = atomicTestNode.get("auto_generated_guid").asText();
						if (testID.contains(testAutoID))
						{
							continue;
						}
						testID.add(testAutoID);
						testNumber += 1;
						AtomicRedTeam atomicTest = objectMapper.treeToValue(atomicTestNode, AtomicRedTeam.class);
						atomicTest.setTechniqueId(technique.getTechniqueId());
						atomicTest.setTechniqueName(technique.getTechniqueName());
						atomicTest.setTechniqueDescription(technique.getTechniqueDescription());
						atomicTest.setTechniquePlatforms(technique.getTechniquePlatforms());
						atomicTest.setTechniqueDomains(technique.getTechniqueDomains());
						atomicTest.setTechniqueUrl(technique.getTechniqueUrl());
						atomicTest.setTechniqueTactics(technique.getTechniqueTactics());
						atomicTest.setTechniqueDetection(technique.getTechniqueDetection());
						atomicTest.setTechniqueIsSubtechnique(technique.isTechniqueIsSubtechnique());
						atomicTest.setTestNumber(testNumber);
						atomicTests.add(atomicTest);
					}
				}
			}
		}
		return atomicTests;
	}

	private void createTitleRow(Sheet sheet)
	{
		sheet.addMergedRegion(new CellRangeAddress(0, 0, 0, 18));
		Row row = sheet.createRow(0);
		row.setHeightInPoints((short) 50);
		Cell mergedCell = row.createCell(0);
		mergedCell.setCellValue("ATOMIC REDTEAM TEST LIBRARY DATA");

		CellStyle titleStyle = sheet.getWorkbook().createCellStyle();
		Font font = sheet.getWorkbook().createFont();
		font.setFontHeightInPoints((short) 20);
		font.setBold(true);
		titleStyle.setFont(font);
		titleStyle.setAlignment(HorizontalAlignment.CENTER);
		titleStyle.setVerticalAlignment(VerticalAlignment.CENTER);
		titleStyle.setBorderBottom(BorderStyle.DOUBLE);
		titleStyle.setBorderTop(BorderStyle.DOUBLE);
		titleStyle.setBorderLeft(BorderStyle.DOUBLE);
		titleStyle.setBorderRight(BorderStyle.DOUBLE);
		mergedCell.setCellStyle(titleStyle);

		for (int i = 1; i <= 18; ++i)
		{
			mergedCell = row.createCell(i);
			mergedCell.setCellStyle(titleStyle);
		}
	}

	private void createHeaderRow(Sheet sheet)
	{
		Row headerRow = sheet.createRow(2);
		headerRow.setHeightInPoints((short) 30);
		CellStyle headerCellStyle = sheet.getWorkbook().createCellStyle();
		Font font = sheet.getWorkbook().createFont();
		font.setBold(true);
		font.setFontHeightInPoints((short) 16);
		headerCellStyle.setFont(font);
		headerCellStyle.setWrapText(true);
		headerCellStyle.setAlignment(HorizontalAlignment.CENTER);
		headerCellStyle.setVerticalAlignment(VerticalAlignment.CENTER);
		headerCellStyle.setBorderBottom(BorderStyle.THIN);
		headerCellStyle.setBorderTop(BorderStyle.THIN);
		headerCellStyle.setBorderLeft(BorderStyle.THIN);
		headerCellStyle.setBorderRight(BorderStyle.THIN);

		sheet.addMergedRegion(new CellRangeAddress(2, 3, 0, 0));
		Cell mergedCell = headerRow.createCell(0);
		mergedCell.setCellValue(HEADERS[0]);
		mergedCell.setCellStyle(headerCellStyle);

		sheet.addMergedRegion(new CellRangeAddress(2, 2, 1, 9));
		mergedCell = headerRow.createCell(1);
		mergedCell.setCellValue("TECHNIQUE");
		mergedCell.setCellStyle(headerCellStyle);

		for (int i = 2; i <= 9; ++i)
		{
			mergedCell = headerRow.createCell(i);
			mergedCell.setCellStyle(headerCellStyle);
		}

		sheet.addMergedRegion(new CellRangeAddress(2, 2, 10, 18));
		mergedCell = headerRow.createCell(10);
		mergedCell.setCellValue("TEST");
		mergedCell.setCellStyle(headerCellStyle);

		for (int i = 11; i <= 18; ++i)
		{
			mergedCell = headerRow.createCell(i);
			mergedCell.setCellStyle(headerCellStyle);
		}
	}

	private void createSubHeaderRow(Sheet sheet)
	{
		Row subHeaderRow = sheet.createRow(3);
		subHeaderRow.setHeight((short) -1);
		CellStyle subHeaderCellStyle = sheet.getWorkbook().createCellStyle();
		Font font = sheet.getWorkbook().createFont();
		font.setBold(true);
		font.setFontHeightInPoints((short) 13);
		subHeaderCellStyle.setFont(font);
		subHeaderCellStyle.setWrapText(true);
		subHeaderCellStyle.setAlignment(HorizontalAlignment.CENTER);
		subHeaderCellStyle.setVerticalAlignment(VerticalAlignment.CENTER);
		subHeaderCellStyle.setBorderBottom(BorderStyle.THIN);
		subHeaderCellStyle.setBorderTop(BorderStyle.THIN);
		subHeaderCellStyle.setBorderLeft(BorderStyle.THIN);
		subHeaderCellStyle.setBorderRight(BorderStyle.THIN);

		for (int i = 1; i < HEADERS.length; i++)
		{
			Cell cell = subHeaderRow.createCell(i);
			cell.setCellValue(HEADERS[i]);
			cell.setCellStyle(subHeaderCellStyle);
		}
	}

	private void createDataCell(Row row, int column, CellStyle style, Object value)
	{
		Cell dataCell = row.createCell(column);
		dataCell.setCellStyle(style);
		if (value instanceof Integer)
		{
			dataCell.setCellValue((Integer) value);
		}
		else if (value instanceof Double)
		{
			dataCell.setCellValue((Double) value);
		}
		else if (value instanceof Boolean)
		{
			dataCell.setCellValue((Boolean) value);
		}
		else
		{
			dataCell.setCellValue(value.toString());
		}
	}

	private void createDataRows(Sheet sheet, List<AtomicRedTeam> atomicTests)
	{
		int rowNum = 4;
		CellStyle contentCellStyle = sheet.getWorkbook().createCellStyle();
		Font font = sheet.getWorkbook().createFont();
		font.setFontHeightInPoints((short) 12);
		contentCellStyle.setFont(font);
		contentCellStyle.setWrapText(true);
		contentCellStyle.setVerticalAlignment(VerticalAlignment.CENTER);
		contentCellStyle.setBorderBottom(BorderStyle.THIN);
		contentCellStyle.setBorderTop(BorderStyle.THIN);
		contentCellStyle.setBorderLeft(BorderStyle.THIN);
		contentCellStyle.setBorderRight(BorderStyle.THIN);

		CellStyle contentCenteredCellStyle = sheet.getWorkbook().createCellStyle();
		contentCenteredCellStyle.setWrapText(true);
		contentCenteredCellStyle.setVerticalAlignment(VerticalAlignment.CENTER);
		contentCenteredCellStyle.setAlignment(HorizontalAlignment.CENTER);
		contentCenteredCellStyle.setBorderBottom(BorderStyle.THIN);
		contentCenteredCellStyle.setBorderTop(BorderStyle.THIN);
		contentCenteredCellStyle.setBorderLeft(BorderStyle.THIN);
		contentCenteredCellStyle.setBorderRight(BorderStyle.THIN);

		for (AtomicRedTeam atomicTest : atomicTests)
		{
			Row dataRow = sheet.createRow(rowNum++);
			dataRow.setHeight((short) -1);

			createDataCell(dataRow, 0, contentCenteredCellStyle, rowNum - 4);

			createDataCell(dataRow, 1, contentCenteredCellStyle, atomicTest.getTechniqueId());

			createDataCell(dataRow, 2, contentCellStyle, atomicTest.getTechniqueName());

			createDataCell(dataRow, 3, contentCellStyle, atomicTest.getTechniqueDescription());

			String techniquePlatforms = (atomicTest.getTechniquePlatforms() == null)
					? ""
					: String.join("\n", atomicTest.getTechniquePlatforms());
			createDataCell(dataRow, 4, contentCellStyle, techniquePlatforms);

			String techniqueDomains = (atomicTest.getTechniqueDomains() == null)
					? ""
					: String.join("\n", atomicTest.getTechniqueDomains());
			createDataCell(dataRow, 5, contentCellStyle, techniqueDomains);

			createDataCell(dataRow, 6, contentCellStyle, atomicTest.getTechniqueUrl());

			String techniqueTactics = (atomicTest.getTechniqueTactics() == null)
					? ""
					: String.join("\n", atomicTest.getTechniqueTactics());
			createDataCell(dataRow, 7, contentCellStyle, techniqueTactics);

			createDataCell(dataRow, 8, contentCellStyle, atomicTest.getTechniqueDetection());

			createDataCell(dataRow, 9, contentCellStyle, atomicTest.isTechniqueIsSubtechnique());

			createDataCell(dataRow, 10, contentCenteredCellStyle, atomicTest.getTestNumber());

			createDataCell(dataRow, 11, contentCellStyle, atomicTest.getTestName());

			createDataCell(dataRow, 12, contentCellStyle, atomicTest.getTestGuid());

			createDataCell(dataRow, 13, contentCellStyle, atomicTest.getTestDescription());

			String testSupportedPlatforms = (atomicTest.getTestSupportedPlatforms() == null)
					? ""
					: String.join("\n", atomicTest.getTestSupportedPlatforms());
			createDataCell(dataRow, 14, contentCellStyle, testSupportedPlatforms);

			String testInputArguments = (atomicTest.getTestInputArguments() == null)
					? ""
					: String.join("\n", atomicTest.getTestInputArguments());
			createDataCell(dataRow, 15, contentCellStyle, testInputArguments);

			String testExecutor = (atomicTest.getTestExecutor() == null)
					? ""
					: String.join("\n", atomicTest.getTestExecutor());
			createDataCell(dataRow, 16, contentCellStyle, testExecutor);

			createDataCell(dataRow, 17, contentCellStyle, atomicTest.getTestDependencyExecutorName());

			String testDependencies = (atomicTest.getTestDependencies() == null)
					? ""
					: String.join("\n", atomicTest.getTestDependencies());
			createDataCell(dataRow, 18, contentCellStyle, testDependencies);
		}
	}

	private void autoSizeColumns(Sheet sheet)
	{
		sheet.setColumnWidth(0, 3000);

		// Technique ID
		sheet.setColumnWidth(1, 5500);

		// Technique Name
		sheet.setColumnWidth(2, 10500);

		// Technique Description
		sheet.setColumnWidth(3, 60000);

		// Technique Platforms
		sheet.setColumnWidth(4, 5000);

		// Technique Domains
		sheet.setColumnWidth(5, 5000);

		// Technique URL
		sheet.setColumnWidth(6, 12000);

		// Technique Tactics
		sheet.setColumnWidth(7, 7000);

		// Technique Detection
		sheet.setColumnWidth(8, 20000);

		// Is Subtechnique
		sheet.setColumnWidth(9, 5000);

		// Test Number
		sheet.setColumnWidth(10, 4000);

		// Test Name
		sheet.setColumnWidth(11, 10500);

		// Test GUID
		sheet.setColumnWidth(12, 11000);

		// Test Description
		sheet.setColumnWidth(13, 19000);

		// Test Supported Platforms
		sheet.setColumnWidth(14, 6000);

		// Test Input Arguments
		sheet.setColumnWidth(15, 14600);

		// Test Executor
		sheet.setColumnWidth(16, 14600);

		// Test Dependency Executor Name
		sheet.setColumnWidth(17, 6500);

		// Test Dependencies
		sheet.setColumnWidth(18, 11500);
	}

	private void hideTechniqueColumns(Sheet sheet)
	{
		for (int i = 3; i < 10; i++)
		{
			sheet.setColumnHidden(i, true);
		}
	}

	private void applyFilter(Sheet sheet)
	{
		// Determine the last row and column with data
		int lastRowNum = sheet.getLastRowNum();
		int lastColNum = sheet.getRow(lastRowNum).getLastCellNum() - 1;

		CellRangeAddress usedRange = new CellRangeAddress(3, lastRowNum, 0, lastColNum);
		sheet.setAutoFilter(usedRange);
	}

	private void writeWorkbook(Workbook workbook) throws IOException
	{
		try (FileOutputStream outputStream = new FileOutputStream(excelFilePath))
		{
			workbook.write(outputStream);
		}
	}

	private void openFile(String filePath)
	{
		try
		{
			File file = new File(filePath);
			if (file.exists())
			{
				Desktop.getDesktop().open(file);
			}
			else
			{
				System.err.println("File not found: " + filePath);
			}
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
	}
}
