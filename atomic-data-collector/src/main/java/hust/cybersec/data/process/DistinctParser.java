package hust.cybersec.data.process;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.*;

public class DistinctParser
{
	private List<String> tacticList = new ArrayList<>();
	private List<String> platformList = new ArrayList<>();

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

	private void getTacticList(JsonNode root, String domain)
	{
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
							tacticList.add(phaseNode.get("phase_name").asText());
						}
					}
				}
			}
		}
	}

	private void getPlatformList(JsonNode root)
	{
		if (root.has("x_mitre_platforms"))
		{
			root = root.get("x_mitre_platforms");
			if (root != null && root.isArray())
			{
				for (JsonNode valueNode : root)
				{
					platformList.add(valueNode.asText());
				}
			}
		}
	}

	private void parseData()
	{
		String jsonDirectoryPath = "./data/mitre-attack/";
		for (int i = 0; i < Constants.DOMAINS.length; ++i)
		{
			String domain = Constants.DOMAINS[i];
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
							getTacticList(techniqueNode, Constants.KILL_CHAIN_NAME[i]);
							if (techniqueNode.has("x_mitre_platforms"))
							{
								getPlatformList(techniqueNode);
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

	public String[] parseDistinctTactic()
	{
		if (tacticList.isEmpty())
		{
			parseData();
		}
		return tacticList.stream().distinct().collect(Collectors.toList()).toArray(new String[0]);
	}

	public String[] parseDistinctPlatform()
	{
		if (platformList.isEmpty())
		{
			parseData();
		}
		return platformList.stream().distinct().collect(Collectors.toList()).toArray(new String[0]);
	}
}
