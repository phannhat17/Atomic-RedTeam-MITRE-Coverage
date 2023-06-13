package hust.cybersec;

import org.json.*;
import java.nio.file.*;
import java.io.*;

public class GetNumTechniquesForEachTactics
{
	// List of tactics
	private final String[] tacticsList = { "collection", "command-and-control", "credential-access", "defense-evasion",
			"discovery", "execution", "exfiltration", "impact", "initial-access", "lateral-movement", "persistence",
			"privilege-escalation", "reconnaissance", "resource-development" };

	// List of domains
	private final String[] domainList = { "enterprise-attack", "ics-attack", "mobile-attack" };

	public void processTechniques()
	{
		for (String domain : domainList)
		{
			long startTime = System.currentTimeMillis();
			try
			{
				// Read JSON file as a string
				String filePath = getFilePath(domain);
				if (filePath == null)
				{
					System.err.println("Invalid file path: " + domain);
					continue;
				}
				String jsonStr = new String(Files.readAllBytes(Paths.get(filePath)));

				// Parse the JSON string
				JSONObject bundleJson = new JSONObject(jsonStr);

				// Get the "objects" array from the bundle
				JSONArray objects = bundleJson.getJSONArray("objects");

				FileWriter myWriter = new FileWriter(getOutputFilePath(domain));

				for (String tactic : tacticsList)
				{
					int count = 0;
					for (int i = 0; i < objects.length(); i++)
					{
						JSONObject obj = objects.getJSONObject(i);
						if (isValidAttackPattern(obj, tactic))
						{
							count++;
						}
					}

					myWriter.write("- " + tactic + ": " + count + "\n");
				}

				myWriter.close();
				long stopTime = System.currentTimeMillis();
				System.out.println("Execution time: " + (stopTime - startTime) + "ms");
			} catch (JSONException e)
			{
				System.err.println("An error occurred while parsing JSON.");
				e.printStackTrace();
			} catch (IOException e)
			{
				System.err.println("An error occurred while reading or writing files.");
				e.printStackTrace();
			}
		}
	}

	private String getFilePath(String domain)
	{
		try
		{
			// Get the absolute path of the base directory
			Path basePath = Paths.get("./data/mitre-attack/").toAbsolutePath().normalize();

			// Resolve the file path based on the technique
			Path filePath = basePath.resolve(domain + ".json");

			// Check if the file path is valid and within the base directory
			if (!Files.isRegularFile(filePath) || !filePath.startsWith(basePath))
			{
				return null;
			}

			return filePath.toString();
		} catch (SecurityException e)
		{
			System.err.println("Insufficient permissions to access the file: " + domain);
			return null;
		}
	}

	private String getOutputFilePath(String domain)
	{
		try
		{
			// Get the absolute path of the base directory
			Path basePath = Paths.get("./data/mitre-attack/").toAbsolutePath().normalize();

			// Resolve the file path for the output file based on the domain
			Path filePath = basePath.resolve(domain + ".txt");

			// Check if the file path is valid and within the base directory
			if (!filePath.startsWith(basePath))
			{
				throw new SecurityException("Invalid file path: " + domain);
			}

			return filePath.toString();
		} catch (SecurityException e)
		{
			System.err.println("Insufficient permissions to access the file: " + domain);
			return null;
		}
	}

	private boolean isValidAttackPattern(JSONObject obj, String tactic)
	{
		if (obj.getString("type").equals("attack-pattern") && !obj.optBoolean("x_mitre_is_subtechnique")
				&& !obj.optBoolean("x_mitre_deprecated", false) && !obj.optBoolean("revoked", false))
		{

			JSONArray externalReferences = obj.getJSONArray("external_references");
			JSONArray killChainPhases = obj.optJSONArray("kill_chain_phases");
			boolean hasCollectionPhase = false;

			if (killChainPhases != null)
			{
				for (int j = 0; j < killChainPhases.length(); j++)
				{
					JSONObject phase = killChainPhases.getJSONObject(j);
					String phaseName = phase.optString("phase_name");
					if (phaseName != null && phaseName.equals(tactic))
					{
						hasCollectionPhase = true;
						break;
					}
				}
			}

			if (hasCollectionPhase)
			{
				for (int j = 0; j < externalReferences.length(); j++)
				{
					JSONObject ref = externalReferences.getJSONObject(j);
					if (ref.has("external_id"))
					{
						String externalId = ref.getString("external_id");
						if (externalId.startsWith("T"))
						{
							return true;
						}
					}
				}
			}
		}

		return false;
	}

	public static void main(String[] args)
	{
		GetNumTechniquesForEachTactics converter = new GetNumTechniquesForEachTactics();
		converter.processTechniques();
	}
}
