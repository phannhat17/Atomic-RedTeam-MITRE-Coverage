package hust.cybersec.functional;

import java.util.*;
import java.io.IOException;
import java.nio.file.*;
import com.fasterxml.jackson.databind.*;

import hust.cybersec.data.process.*;

public class CoverageAnalyser
{
	private DataTree enterpriseTree;
	private DataTree mobileTree;
	private DataTree icsTree;
	private String[] path = new String[4];

	public void analyse()
	{
		preprocessData();
		double ratio = calculateCoverageRatio();

		generateChart();
	}

	private void initialDataTree()
	{
		for (int i = 0; i < Constants.DOMAINS.length; ++i)
		{
			if (i == 0)
			{
				enterpriseTree = new DataTree(Constants.DOMAINS[i]);
			} else if (i == 1)
			{
				mobileTree = new DataTree(Constants.DOMAINS[i]);
			} else
			{
				icsTree = new DataTree(Constants.DOMAINS[i]);
			}
		}
	}

	private String getNodeValue(JsonNode node, String fieldName)
	{
		if (node.has(fieldName))
		{
			return node.get(fieldName).asText();
		}
		return "";
	}

	private boolean checkValid(JsonNode root)
	{
		if (!getNodeValue(root, "type").equals("attack-pattern"))
		{
			return false;
		}
		if (getNodeValue(root, "revoked").equals("true"))
		{
			return false;
		}
		if (getNodeValue(root, "x_mitre_deprecated").equals("true"))
		{
			return false;
		}
		if (!root.has("external_references"))
		{
			return false;
		}
		JsonNode externalReferencesNode = root.get("external_references");
		JsonNode externalNode = null;
		if (externalReferencesNode != null && externalReferencesNode.isArray())
		{
			for (JsonNode referenceNode : externalReferencesNode)
			{
				if (referenceNode.has("external_id")
						&& referenceNode.get("source_name").asText().equals("mitre-attack"))
				{
					if (referenceNode.get("external_id").asText().startsWith("T"))
					{
						externalNode = referenceNode;
						break;
					}
				}
			}
		}
		if (externalNode == null)
		{
			return false;
		}
		return true;
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
					if (phaseNode.has("kill_chain_name") && phaseNode.has("phase_name"))
					{
						if (phaseNode.get("kill_chain_name").asText().equals(domain))
						{
							tacticSubList.add(phaseNode.get("phase_name").asText());
						}
					}
				}
			}
		}
		return tacticSubList.toArray(new String[0]);
	}

	private String[] getPlatformList(JsonNode root)
	{
		List<String> platformSubList = new ArrayList<>();
		if (root.has("x_mitre_platforms"))
		{
			root = root.get("x_mitre_platforms");
			if (root != null && root.isArray())
			{
				for (JsonNode valueNode : root)
				{
					platformSubList.add(valueNode.asText());
				}
			}
		}
		return platformSubList.toArray(new String[0]);
	}

	private void assignMitreNodeValue(int domainInt, String[] pathNode)
	{
		switch (domainInt)
		{
			case 0:
				Object value = enterpriseTree.getValue(pathNode);
				if (value == null)
					return;
				Pair pairValue = (Pair) value;
				pairValue.setFirst_mitre(pairValue.getFirst_mitre() + 1);
//				pairValue.setSecond_atomic(pairValue.getSecond_atomic() + 1); 
				enterpriseTree.setValue(pathNode, pairValue);
				return;
			case 1:
				value = mobileTree.getValue(pathNode);
				if (value == null)
					return;
				pairValue = (Pair) value;
				pairValue.setFirst_mitre(pairValue.getFirst_mitre() + 1);
				mobileTree.setValue(pathNode, pairValue);
				return;
			case 2:
				value = icsTree.getValue(pathNode);
				if (value == null)
					return;
				pairValue = (Pair) value;
				pairValue.setFirst_mitre(pairValue.getFirst_mitre() + 1);
				icsTree.setValue(pathNode, pairValue);
		}
	}

	private void assignLeafValue(int domainInt, String[] pathNode)
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
		}
	}

	private void mapMitreData()
	{
		String jsonDirectoryPath = "./data/mitre-attack/";
		path[3] = "Mitre.Technique";
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
						if (checkValid(techniqueNode))
						{
							assignMitreNodeValue(i, Arrays.copyOfRange(path, 0, 1));
							String[] tacticSubList = getTacticList(techniqueNode, Constants.KILL_CHAIN_NAME[i]);
							if (techniqueNode.has("x_mitre_platforms"))
							{
								String[] platformSubList = getPlatformList(techniqueNode);
								for (String tactic : tacticSubList)
								{
									path[1] = tactic;
									assignMitreNodeValue(i, Arrays.copyOfRange(path, 0, 2));
									for (String platform : platformSubList)
									{
										path[2] = platform;
										assignMitreNodeValue(i, Arrays.copyOfRange(path, 0, 3));
										assignLeafValue(i, path);
									}
								}
							}
						}
					}
				}
			} catch (IOException e)
			{
				System.out.println("Path not found!");
				e.printStackTrace();
			}
		}
	}

	private void mapAtomicData()
	{

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

	}

	private double calculateCoverageRatio()
	{
		return 0.0;
	}

	private void generateChart()
	{

	}

	public static void main(String args[])
	{
		CoverageAnalyser coverage = new CoverageAnalyser();
		coverage.preprocessData();

//		coverage.path[3] = "Mitre.Technique";
//		
//		String[] tempPath;
//		
//		for (int i = 0; i < Constants.DOMAINS.length; ++i)
//		{
//			int total = 0;
//			String domain = Constants.DOMAINS[i];
//			coverage.path[0] = domain;
//			for (String tactic : Constants.TACTICS)
//			{
//				coverage.path[1] = tactic;
//				for (String platform : Constants.PLATFORMS)
//				{
//					coverage.path[2] = platform;
//					Integer value = null;
//					if (i == 0)
//					{
//						value = (Integer) coverage.enterpriseTree.getValue(coverage.path);
//						total += value;
//					} else if (i == 1)
//					{
//						value = (Integer) coverage.mobileTree.getValue(coverage.path);
//						total += value;
//					} else
//					{
//						value = (Integer) coverage.icsTree.getValue(coverage.path);
//						total += value;
//					}
//					System.out.println(Arrays.toString(coverage.path) + ": " + value);
//				}
//			}
//			System.out.println("Total for " + domain + ": " + total);
//		}
//		
//		coverage.path[0] = Constants.DOMAINS[0];
//		tempPath = Arrays.copyOfRange(coverage.path, 0, 1);
//		Pair pairValue = (Pair) coverage.enterpriseTree.getValue(tempPath);
//		System.out.println(Arrays.toString(tempPath) + pairValue.getFirst_mitre() + " " + pairValue.getSecond_atomic());
//		coverage.path[0] = Constants.DOMAINS[1];
//		tempPath = Arrays.copyOfRange(coverage.path, 0, 1);
//		pairValue = (Pair) coverage.mobileTree.getValue(tempPath);
//		System.out.println(Arrays.toString(tempPath) + pairValue.getFirst_mitre() + " " + pairValue.getSecond_atomic());
//		coverage.path[0] = Constants.DOMAINS[2];
//		tempPath = Arrays.copyOfRange(coverage.path, 0, 1);
//		pairValue = (Pair) coverage.icsTree.getValue(tempPath);
//		System.out.println(Arrays.toString(tempPath) + pairValue.getFirst_mitre() + " " + pairValue.getSecond_atomic());
	}

}
