package hust.cybersec.data.process;

import java.util.*;
import java.nio.file.*;
import java.io.IOException;

import com.fasterxml.jackson.databind.*;

public class DistinctParser
{
	private HashSet<String> tacticList = new HashSet<>();
	private HashSet<String> platformList = new HashSet<>();

	private JsonNodeHandler jsonHandler = new JsonNodeHandler();

	private void getTacticList(JsonNode root, String domain)
	{
		if (root.has("kill_chain_phases"))
		{
			root = root.get("kill_chain_phases");
			if (root != null && root.isArray())
			{
				for (JsonNode phaseNode : root)
				{
					if (checkPhaseNode(phaseNode, domain))
					{
						tacticList.add(phaseNode.get("phase_name").asText().toLowerCase());
					}
				}
			}
		}
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

	private void getPlatformList(JsonNode root, String fieldName)
	{
		if (root.has(fieldName))
		{
			root = root.get(fieldName);
			if (root != null && root.isArray())
			{
				for (JsonNode valueNode : root)
				{
					platformList.add(valueNode.asText().toLowerCase());
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
						if (jsonHandler.checkValid(techniqueNode))
						{
							getTacticList(techniqueNode, Constants.KILL_CHAIN_NAME[i]);
							if (techniqueNode.has("x_mitre_platforms"))
							{
								getPlatformList(techniqueNode, "x_mitre_platforms");
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

	public String[] parseDistinctTactic()
	{
		if (tacticList.isEmpty())
		{
			parseData();
		}
		return tacticList.toArray(new String[0]);
	}

	public String[] parseDistinctPlatform()
	{
		if (platformList.isEmpty())
		{
			parseData();
		}
		return platformList.toArray(new String[0]);
	}
}
