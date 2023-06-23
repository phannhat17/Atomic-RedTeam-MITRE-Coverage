package hust.cybersec.functional;

import java.util.*;
import java.nio.file.*;
import java.io.IOException;

import com.fasterxml.jackson.databind.*;

import hust.cybersec.data.process.*;

public class CoverageAnalyser
{
	private DataTree enterpriseTree;
	private DataTree mobileTree;
	private DataTree icsTree;
	private String[] path = new String[4];

	private JsonNodeHandler jsonHandler = new JsonNodeHandler();

	public void analyse()
	{
		preprocessData();
		double ratio = calculateCoverageRatio();

		generateChart();
	}

	private void initialDataTree()
	{
		enterpriseTree = new DataTree(Constants.DOMAINS[0]);
		mobileTree = new DataTree(Constants.DOMAINS[1]);
		icsTree = new DataTree(Constants.DOMAINS[2]);
	}

	private String[] getTacticList(JsonNode root, String domain)
	{
		List<String> tacticSubList = new ArrayList<>();
		if (root.has("kill_chain_phases"))
		{
			root = root.get("kill_chain_phases");
			if (root != null && root.isArray())
			{
				for (JsonNode phaseNode : root)
				{
					if (checkPhaseNode(phaseNode, domain))
					{
						tacticSubList.add(phaseNode.get("phase_name").asText().toLowerCase());
					}
				}
			}
		}
		return tacticSubList.toArray(new String[0]);
	}

	private boolean checkPhaseNode(JsonNode phaseNode, String domain)
	{
		if (!phaseNode.has("kill_chain_name") || !phaseNode.has("phase_name"))
		{
			return false;
		}
		String killChainName = phaseNode.get("kill_chain_name").asText();
		return killChainName.equals(domain);
	}

	private String[] getPlatformList(JsonNode root, String fieldName)
	{
		List<String> platformSubList = new ArrayList<>();
		if (root.has(fieldName))
		{
			root = root.get(fieldName);
			if (root != null && root.isArray())
			{
				for (JsonNode valueNode : root)
				{
					platformSubList.add(valueNode.asText().toLowerCase());
				}
			}
		}
		return platformSubList.toArray(new String[0]);
	}

	private void assignNodeValue(int domainInt, String[] pathNode, int elementInt, int valueAdd)
	{
		switch (domainInt)
		{
			case 0:
				Object value = enterpriseTree.getValue(pathNode);
				if (value == null || elementInt != 1) return;
				Triple tripleValue = (Triple) value;
				tripleValue.setMitreNode(tripleValue.getMitreNode() + valueAdd);
				enterpriseTree.setValue(pathNode, tripleValue);
				return;
			case 1:
				value = mobileTree.getValue(pathNode);
				if (value == null || elementInt != 1) return;
				tripleValue = (Triple) value;
				tripleValue.setMitreNode(tripleValue.getMitreNode() + valueAdd);
				mobileTree.setValue(pathNode, tripleValue);
				return;
			case 2:
				value = icsTree.getValue(pathNode);
				if (value == null || elementInt != 1) return;
				tripleValue = (Triple) value;
				tripleValue.setMitreNode(tripleValue.getMitreNode() + valueAdd);
				icsTree.setValue(pathNode, tripleValue);
				return;
			default:
				return;
		}
	}

	private Triple addNodeValue(Object value, int elementSubInt, int valueAdd)
	{
		Triple tripleValue = (Triple) value;
		Pair pairValue = tripleValue.getAtomicNode();
		if (elementSubInt == 1)
		{
			pairValue.setAtomicTechnique(pairValue.getAtomicTechnique() + valueAdd);
			tripleValue.setAtomicNode(pairValue);
		}
		else
		{
			pairValue.setAtomicTest(pairValue.getAtomicTest() + valueAdd);
			tripleValue.setAtomicNode(pairValue);
		}
		return tripleValue;
	}

	private void assignNodeValue(int domainInt, String[] pathNode, int elementInt, int elementSubInt, int valueAdd)
	{
		switch (domainInt)
		{
			case 0:
				Object value = enterpriseTree.getValue(pathNode);
				if (value == null || elementInt != 2) return;
				Triple tripleValue = addNodeValue(value, elementSubInt, valueAdd);
				enterpriseTree.setValue(pathNode, tripleValue);
				return;
			case 1:
				value = mobileTree.getValue(pathNode);
				if (value == null || elementInt != 2) return;
				tripleValue = addNodeValue(value, elementSubInt, valueAdd);
				mobileTree.setValue(pathNode, tripleValue);
				return;
			case 2:
				value = icsTree.getValue(pathNode);
				if (value == null || elementInt != 2) return;
				tripleValue = addNodeValue(value, elementSubInt, valueAdd);
				icsTree.setValue(pathNode, tripleValue);
				return;
			default:
				return;
		}
	}

	private void assignMitreValue(int domainInt, String[] pathNode)
	{
		switch (domainInt)
		{
			case 0:
				Object value = enterpriseTree.getValue(pathNode);
				value = (value == null) ? null : (Integer) value + 1;
				enterpriseTree.setValue(pathNode, value);
				return;
			case 1:
				value = mobileTree.getValue(pathNode);
				value = (value == null) ? null : (Integer) value + 1;
				mobileTree.setValue(pathNode, value);
				return;
			case 2:
				value = icsTree.getValue(pathNode);
				value = (value == null) ? null : (Integer) value + 1;
				icsTree.setValue(pathNode, value);
				return;
			default:
				return;
		}
	}

	private Pair addAtomicValue(Object value, int elementInt, int valueAdd)
	{
		Pair pairValue = (Pair) value;
		if (elementInt == 1)
		{
			pairValue.setAtomicTechnique(pairValue.getAtomicTechnique() + valueAdd);
		}
		else
		{
			pairValue.setAtomicTest(pairValue.getAtomicTest() + valueAdd);
		}
		return pairValue;
	}

	private void assignAtomicValue(int domainInt, String[] pathNode, int elementInt, int valueAdd)
	{
		switch (domainInt)
		{
			case 0:
				Object value = enterpriseTree.getValue(pathNode);
				if (value == null || elementInt > 2 || elementInt < 1) return;
				Pair pairValue = addAtomicValue(value, elementInt, valueAdd);
				enterpriseTree.setValue(pathNode, pairValue);
				return;
			case 1:
				value = mobileTree.getValue(pathNode);
				if (value == null || elementInt > 2 || elementInt < 1) return;
				pairValue = addAtomicValue(value, elementInt, valueAdd);
				mobileTree.setValue(pathNode, pairValue);
				return;
			case 2:
				value = icsTree.getValue(pathNode);
				if (value == null || elementInt > 2 || elementInt < 1) return;
				pairValue = addAtomicValue(value, elementInt, valueAdd);
				icsTree.setValue(pathNode, pairValue);
				return;
			default:
				return;
		}
	}

	private void mapMitreData()
	{
		String jsonDirectoryPath = "./data/mitre-attack/";
		path[3] = "Mitre.Total";
		for (int i = 0; i < Constants.DOMAINS.length; ++i)
		{
			String domain = Constants.DOMAINS[i];
			path[0] = domain;
			try
			{
				String jsonData = new String(Files.readAllBytes(Paths.get(jsonDirectoryPath + domain + ".json")));
				ObjectMapper objectMapper = new ObjectMapper();
				JsonNode rootData = objectMapper.readTree(jsonData);
				rootData = rootData.get("objects");
				if (rootData != null && rootData.isArray())
				{
					for (JsonNode techniqueNode : rootData)
					{
						if (jsonHandler.checkValid(techniqueNode))
						{
							assignNodeValue(i, Arrays.copyOfRange(path, 0, 1), 1, 1);
							String[] tacticSubList = getTacticList(techniqueNode, Constants.KILL_CHAIN_NAME[i]);
							if (tacticSubList.length > 0 && techniqueNode.has("x_mitre_platforms"))
							{
								String[] platformSubList = getPlatformList(techniqueNode, "x_mitre_platforms");
								if (platformSubList.length == 0)
								{
									continue;
								}
								for (int j = 0; j < tacticSubList.length; ++j)
								{
									String tactic = tacticSubList[j];
									path[1] = tactic;
									assignNodeValue(i, Arrays.copyOfRange(path, 0, 2), 1, 1);
									for (String platform : platformSubList)
									{
										path[2] = platform;
										assignMitreValue(i, path);
										if (j == tacticSubList.length - 1)
										{
											assignNodeValue(i, Arrays.copyOfRange(path, 0, 3), 1, 1);
										}
									}
								}
							}
						}
					}
				}
			}
			catch (IOException e)
			{
				System.out.println("Path not found!");
				e.printStackTrace();
			}
		}
	}

	private String[] getDomainList(JsonNode root)
	{
		List<String> platformSubList = new ArrayList<>();
		if (root.has("x_mitre_domains"))
		{
			root = root.get("x_mitre_domains");
			if (root != null && root.isArray())
			{
				for (JsonNode valueNode : root)
				{
					platformSubList.add(valueNode.asText().toLowerCase());
				}
			}
		}
		return platformSubList.toArray(new String[0]);
	}

	private Integer getDomainInt(String domain)
	{
		for (int i = 0; i < Constants.DOMAINS.length; ++i)
		{
			if (domain.toLowerCase().equals(Constants.DOMAINS[i]))
			{
				return i;
			}
		}
		return null;
	}

	private String[] getSupportedPlatformList(JsonNode root, String fieldName)
	{
		List<String> platformSubList = new ArrayList<>();
		if (root.has(fieldName))
		{
			root = root.get(fieldName);
			if (root != null && root.isArray())
			{
				for (JsonNode valueNode : root)
				{
					platformSubList.add(valueNode.asText().toLowerCase());
				}
			}
		}
		return platformSubList.toArray(new String[0]);
	}

	private String convertPlatformName(String atomicPlatform)
	{
		if (atomicPlatform.contains("-"))
		{
			String[] words = atomicPlatform.split("-");
			return String.join(" ", words);
		}
		if (atomicPlatform.contains(":"))
		{
			String[] words = atomicPlatform.split(":");
			return words[0];
		}
		return atomicPlatform;
	}

	private void extractAtomicData(JsonNode techniqueNode, JsonNode atomicTestsNode, String[] domainSubList)
	{
		for (String domain : domainSubList)
		{
			Integer domainInt = getDomainInt(domain);
			if (domainInt != null)
			{
				int domainIndex = domainInt;
				path[0] = domain;
				String[] tacticSubList = getTacticList(techniqueNode, Constants.KILL_CHAIN_NAME[domainInt]);
				if (tacticSubList.length == 0)
				{
					continue;
				}
				int totalTest = atomicTestsNode.size();

				assignNodeValue(domainIndex, Arrays.copyOfRange(path, 0, 1), 2, 1, 1);
				assignNodeValue(domainIndex, Arrays.copyOfRange(path, 0, 1), 2, 2, totalTest);

				for (int i = 0; i < tacticSubList.length; ++i)
				{
					String tactic = tacticSubList[i];
					path[1] = tactic;

					HashSet<String> testID = new HashSet<>();
					HashSet<String> platformSubList = new HashSet<>();

					assignNodeValue(domainIndex, Arrays.copyOfRange(path, 0, 2), 2, 1, 1);
					assignNodeValue(domainIndex, Arrays.copyOfRange(path, 0, 2), 2, 2, totalTest);

					for (JsonNode atomicTestNode : atomicTestsNode)
					{
						String testAutoID = atomicTestNode.get("auto_generated_guid").asText();
						if (testID.contains(testAutoID))
						{
							continue;
						}
						testID.add(testAutoID);
						String[] supportedPlatform = getSupportedPlatformList(atomicTestNode, "supported_platforms");
						for (String platform : supportedPlatform)
						{
							platform = convertPlatformName(platform);
							path[2] = platform;
							assignAtomicValue(domainIndex, path, 2, 1);
							if (i == tacticSubList.length - 1)
							{
								assignNodeValue(domainIndex, Arrays.copyOfRange(path, 0, 3), 2, 2, 1);
							}
							if (!platformSubList.contains(platform))
							{
								assignAtomicValue(domainIndex, path, 1, 1);
								platformSubList.add(platform);
								if (i == tacticSubList.length - 1)
								{
									assignNodeValue(domainIndex, Arrays.copyOfRange(path, 0, 3), 2, 1, 1);
								}
							}
						}
					}
				}
			}
		}
	}

	private void mapAtomicData()
	{
		HashSet<String> techniqueID = new HashSet<>();
		String jsonPath = "./data/atomic/atomic-all.json";
		path[3] = "Atomic.Total";
		try
		{
			String jsonData = new String(Files.readAllBytes(Paths.get(jsonPath)));
			ObjectMapper objectMapper = new ObjectMapper();
			JsonNode rootData = objectMapper.readTree(jsonData);

			for (JsonNode tacticNode : rootData)
			{
				for (JsonNode list : tacticNode)
				{
					JsonNode techniqueNode = list.get("technique");
					JsonNode atomicTestsNode = list.get("atomic_tests");
					if (jsonHandler.checkValid(techniqueNode) && atomicTestsNode != null && atomicTestsNode.isArray()
							&& !atomicTestsNode.isEmpty() && techniqueNode.has("id"))
					{
						String techniqueAutoID = techniqueNode.get("id").asText();
						if (techniqueID.contains(techniqueAutoID))
						{
							continue;
						}
						techniqueID.add(techniqueAutoID);
						String[] domainSubList = getDomainList(techniqueNode);
						extractAtomicData(techniqueNode, atomicTestsNode, domainSubList);
					}
				}
			}
		}
		catch (IOException e)
		{
			System.out.println("Path not found!");
			e.printStackTrace();
		}
	}

	private void buildDataTree()
	{
		initialDataTree();
		mapMitreData();
		mapAtomicData();
	}

	private void preprocessData()
	{
		buildDataTree();
		// This method hasn't finished yet
	}

	private double calculateCoverageRatio()
	{
		// This method hasn't finished yet
		return 0.0;
	}

	private void generateChart()
	{
		// This method hasn't finished yet
	}

	public static void main(String[] args)
	{
		CoverageAnalyser coverage = new CoverageAnalyser();
		coverage.preprocessData();

		coverage.path[3] = "Atomic.Total";

		// int total = 0;
		String domain = Constants.DOMAINS[0];
		coverage.path[0] = domain;
		for (String platform : Constants.PLATFORMS)
		{
			coverage.path[2] = platform;
			Pair pairValue = new Pair(0, 0);
			for (String tactic : Constants.TACTICS)
			{
				coverage.path[1] = tactic;
				Triple value = (Triple) coverage.enterpriseTree.getValue(Arrays.copyOfRange(coverage.path, 0, 3));
				pairValue.setAtomicTechnique(
						pairValue.getAtomicTechnique() + value.getAtomicNode().getAtomicTechnique());
				pairValue.setAtomicTest(pairValue.getAtomicTest() + value.getAtomicNode().getAtomicTest());
			}
			coverage.path[1] = null;
			// for (String platform : Constants.PLATFORMS)
			// {
			// coverage.path[2] = platform;
			// Pair value = null;
			// value = (Pair) coverage.enterpriseTree.getValue(coverage.path);
			// System.out.println(Arrays.toString(coverage.path) + ": " +
			// value.getAtomicTechnique() + ", "
			// + value.getAtomicTest());
			// coverage.path[2] = null;
			// }
			// Triple value = (Triple)
			// coverage.enterpriseTree.getValue(Arrays.copyOfRange(coverage.path, 0, 2));
			System.out.println(Arrays.toString(Arrays.copyOfRange(coverage.path, 0, 3)) + ": "
					+ pairValue.getAtomicTechnique() + ", " + pairValue.getAtomicTest());
		}
		// System.out.println("Total for " + domain + ": " + total);

		// String[] tempPath;

		// coverage.path[0] = Constants.DOMAINS[0];
		// tempPath = Arrays.copyOfRange(coverage.path, 0, 1);
		// Triple tripleValue = (Triple) coverage.enterpriseTree.getValue(tempPath);
		// Pair pairValue = tripleValue.getAtomicNode();
		// System.out.println(Arrays.toString(tempPath) + ": " + tripleValue.getMitreNode() + " <"
		// 		+ pairValue.getAtomicTechnique() + ", " + pairValue.getAtomicTest() + ">");
		// coverage.path[0] = Constants.DOMAINS[1];
		// tempPath = Arrays.copyOfRange(coverage.path, 0, 1);
		// tripleValue = (Triple) coverage.mobileTree.getValue(tempPath);
		// pairValue = tripleValue.getAtomicNode();
		// System.out.println(Arrays.toString(tempPath) + ": " + tripleValue.getMitreNode() + " <"
		// 		+ pairValue.getAtomicTechnique() + ", " + pairValue.getAtomicTest() + ">");
		// coverage.path[0] = Constants.DOMAINS[2];
		// tempPath = Arrays.copyOfRange(coverage.path, 0, 1);
		// tripleValue = (Triple) coverage.icsTree.getValue(tempPath);
		// pairValue = tripleValue.getAtomicNode();
		// System.out.println(Arrays.toString(tempPath) + ": " + tripleValue.getMitreNode() + " <"
		// 		+ pairValue.getAtomicTechnique() + ", " + pairValue.getAtomicTest() + ">");
	}
}
