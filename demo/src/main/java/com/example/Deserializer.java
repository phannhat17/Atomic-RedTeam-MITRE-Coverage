package com.example;

import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.databind.*;

import java.io.*;
import java.util.*;

public class Deserializer extends JsonDeserializer<Object>
{
	private ObjectMapper objectMapper = new ObjectMapper();

	@Override
	public Object deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException
	{
		JsonNode node = jsonParser.getCodec().readTree(jsonParser);

		if (node.has("auto_generated_guid"))
		{
			return deserializeAtomicRedTeam(node);
		} 
		else
		{
			return deserializeMitreAttackFramework(node);
		}
	}

	private String[] parseStringArray(ObjectMapper objectMapper, JsonNode jsonNode)
			throws JsonProcessingException, IllegalArgumentException
	{
		return objectMapper.treeToValue(jsonNode, String[].class);
	}

	private String[] parseTactics(ObjectMapper objectMapper, JsonNode jsonNode)
	{
		List<String> phaseNames = new ArrayList<String>();
		if (jsonNode != null && jsonNode.isArray())
		{
			for (JsonNode phaseNode : jsonNode)
			{
				if (phaseNode.has("phase_name"))
				{
					String phaseName = phaseNode.get("phase_name").asText();
					phaseNames.add(phaseName);
				}
			}
		}
		return phaseNames.toArray(new String[0]);
	}

	private String[] parseInputArguments(JsonNode jsonNode)
	{
		List<String> inputArgumentsList = new ArrayList<String>();
		if (jsonNode != null && jsonNode.isObject())
		{
			Iterator<Map.Entry<String, JsonNode>> argumentFields = jsonNode.fields();
			while (argumentFields.hasNext())
			{
				Map.Entry<String, JsonNode> argumentField = argumentFields.next();
				StringBuilder combinedValues = new StringBuilder();
				String nodeName = argumentField.getKey();
				combinedValues.append("* ").append(nodeName).append(":\n        ");
				JsonNode subNode = argumentField.getValue();
				Iterator<Map.Entry<String, JsonNode>> subNodeFileds = subNode.fields();
				while (subNodeFileds.hasNext())
				{
					Map.Entry<String, JsonNode> subNodeField = subNodeFileds.next();
					String subNodeName = subNodeField.getKey();
					JsonNode subNodeValue = subNodeField.getValue();
					if (subNodeValue != null)
					{
						combinedValues.append(subNodeName).append(": ").append(subNodeValue).append("\n        ");
					}
				}
				inputArgumentsList.add(combinedValues.toString());
			}
		}
		return inputArgumentsList.toArray(new String[0]);
	}

	private String[] parseExecutor(JsonNode jsonNode)
	{
		List<String> executorList = new ArrayList<String>();
		if (jsonNode != null && jsonNode.isObject())
		{
			Iterator<Map.Entry<String, JsonNode>> executorFields = jsonNode.fields();
			while (executorFields.hasNext())
			{
				Map.Entry<String, JsonNode> executorField = executorFields.next();
				StringBuilder combinedValues = new StringBuilder();
				String nodeName = executorField.getKey();
				combinedValues.append("* ").append(nodeName).append(": ");
				JsonNode nodeValue = executorField.getValue();
				if (nodeValue != null)
				{
					combinedValues.append(nodeValue);
				}
				executorList.add(combinedValues.toString());
			}
		}
		return executorList.toArray(new String[0]);
	}

	private String[] parseDependencies(JsonNode jsonNode)
	{
		List<String> dependenciesList = new ArrayList<String>();
		if (jsonNode != null && jsonNode.isArray())
		{
			for (JsonNode dependencyNode : jsonNode)
			{
				Iterator<Map.Entry<String, JsonNode>> dependencyFields = dependencyNode.fields();
				while (dependencyFields.hasNext())
				{
					Map.Entry<String, JsonNode> dependencyField = dependencyFields.next();
					StringBuilder combinedValues = new StringBuilder();
					String nodeName = dependencyField.getKey();
					JsonNode nodeValue = dependencyField.getValue();
					if (nodeValue != null)
					{
						combinedValues.append("* ").append(nodeName).append(": ").append(nodeValue);
					}
					dependenciesList.add(combinedValues.toString());
				}
				dependenciesList.add("\n");
			}
		}
		return dependenciesList.toArray(new String[0]);
	}

	private MitreAttackFramework deserializeMitreAttackFramework(JsonNode node)
			throws JsonProcessingException, IllegalArgumentException
	{

		JsonNode externalReferencesNode = node.get("external_references");
		JsonNode externalNode = null;
		if (externalReferencesNode != null && externalReferencesNode.isArray())
		{
			for (JsonNode referenceNode : externalReferencesNode)
			{
				if (referenceNode.has("external_id")
						&& referenceNode.get("source_name").asText().equals("mitre-attack"))
				{
					externalNode = referenceNode;
					break;
				}
			}
		}
		String techniqueId = externalNode.get("external_id").asText();

		String techniqueName = node.get("name").asText();

		String techniqueDescription = node.get("description").asText();

		String[] techniquePlatforms = parseStringArray(objectMapper, node.get("x_mitre_platforms"));

		String[] techniqueDomains = parseStringArray(objectMapper, node.get("x_mitre_domains"));

		String techniqueUrl = externalNode.get("url").asText();

		String[] techniqueTactic = parseTactics(objectMapper, node.get("kill_chain_phases"));

		String techniqueDetection = node.has("x_mitre_detection")? node.get("x_mitre_detection").asText() : "";

		boolean techniqueIsSubtechnique = node.get("x_mitre_is_subtechnique").asBoolean();

		return new MitreAttackFramework(techniqueId, techniqueName, techniqueDescription, techniquePlatforms,
				techniqueDomains, techniqueUrl, techniqueTactic, techniqueDetection, techniqueIsSubtechnique);
	}

	private AtomicRedTeam deserializeAtomicRedTeam(JsonNode node)
			throws JsonProcessingException, IllegalArgumentException
	{
		String testName = node.get("name").asText();

		String testGuid = node.get("auto_generated_guid").asText();

		String testDescription = node.get("description").asText();

		String[] testSupportedPlatforms = parseStringArray(objectMapper, node.get("supported_platforms"));

		String[] testInputArguments = parseInputArguments(node.get("input_arguments"));

		String[] testExecutor = parseExecutor(node.get("executor"));

		String testDependencyExecutorName = node.has("dependency_executor_name")
				? node.get("dependency_executor_name").asText()
				: "";

		String[] testDependencies = node.has("dependencies") ? parseDependencies(node.get("dependencies")) : null;

		return new AtomicRedTeam(testName, testGuid, testDescription, testSupportedPlatforms, testInputArguments,
				testExecutor, testDependencyExecutorName, testDependencies);
	}
}
