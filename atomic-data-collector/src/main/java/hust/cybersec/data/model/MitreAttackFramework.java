package hust.cybersec.data.model;

import java.net.URISyntaxException;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import hust.cybersec.data.collector.DataRetriever;
import hust.cybersec.data.process.Deserializer;

@JsonDeserialize(using = Deserializer.class)
@JsonIgnoreProperties(ignoreUnknown = true)
public class MitreAttackFramework
{
	private String techniqueId;

	@JsonProperty("name")
	private String techniqueName;

	@JsonProperty("description")
	private String techniqueDescription;

	@JsonProperty("x_mitre_platforms")
	private String[] techniquePlatforms;

	@JsonProperty("x_mitre_domains")
	private String[] techniqueDomains;

	private String techniqueUrl;

	private String[] techniqueTactics;

	@JsonProperty("x_mitre_detection")
	private String techniqueDetection;

	@JsonProperty("x_mitre_is_subtechnique")
	private boolean techniqueIsSubtechnique;

	public MitreAttackFramework()
	{

	}

	public MitreAttackFramework(String techniqueId, String techniqueName, String techniqueDescription,
			String[] techniquePlatforms, String[] techniqueDomains, String techniqueUrl, String[] techniqueTactics,
			String techniqueDetection, boolean techniqueIsSubtechnique)
	{
		this.techniqueId = techniqueId;
		this.techniqueName = techniqueName;
		this.techniqueDescription = techniqueDescription;
		this.techniquePlatforms = techniquePlatforms;
		this.techniqueDomains = techniqueDomains;
		this.techniqueUrl = techniqueUrl;
		this.techniqueTactics = techniqueTactics;
		this.techniqueDetection = techniqueDetection;
		this.techniqueIsSubtechnique = techniqueIsSubtechnique;
	}

	public String getTechniqueId()
	{
		return techniqueId;
	}

	public String getTechniqueName()
	{
		return techniqueName;
	}

	public void setTechniqueId(String techniqueId)
	{
		this.techniqueId = techniqueId;
	}

	public void setTechniqueName(String techniqueName)
	{
		this.techniqueName = techniqueName;
	}

	public void setTechniqueDescription(String techniqueDescription)
	{
		this.techniqueDescription = techniqueDescription;
	}

	public void setTechniquePlatforms(String[] techniquePlatforms)
	{
		this.techniquePlatforms = techniquePlatforms;
	}

	public void setTechniqueDomains(String[] techniqueDomains)
	{
		this.techniqueDomains = techniqueDomains;
	}

	public void setTechniqueUrl(String techniqueUrl)
	{
		this.techniqueUrl = techniqueUrl;
	}

	public void setTechniqueTactics(String[] techniqueTactics)
	{
		this.techniqueTactics = techniqueTactics;
	}

	public void setTechniqueDetection(String techniqueDetection)
	{
		this.techniqueDetection = techniqueDetection;
	}

	public void setTechniqueIsSubtechnique(boolean techniqueIsSubtechnique)
	{
		this.techniqueIsSubtechnique = techniqueIsSubtechnique;
	}

	public String getTechniqueDescription()
	{
		return techniqueDescription;
	}

	public String[] getTechniquePlatforms()
	{
		return techniquePlatforms;
	}

	public String[] getTechniqueDomains()
	{
		return techniqueDomains;
	}

	public String getTechniqueUrl()
	{
		return techniqueUrl;
	}

	public String[] getTechniqueTactics()
	{
		return techniqueTactics;
	}

	public String getTechniqueDetection()
	{
		return techniqueDetection;
	}

	public boolean isTechniqueIsSubtechnique()
	{
		return techniqueIsSubtechnique;
	}

	public void downloadData() throws URISyntaxException
	{
		String mitreURL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/";
		String mitreDirectory = "./data/mitre-attack";
		
		// Array of files to download
		String[] mitreFiles = { "enterprise-attack/enterprise-attack.json", "mobile-attack/mobile-attack.json",
				"ics-attack/ics-attack.json" };

		DataRetriever mitreDownloader = new DataRetriever(mitreURL, mitreDirectory, mitreFiles);
		mitreDownloader.download();
	}

	public static void main(String[] args) throws URISyntaxException
	{
		MitreAttackFramework mitre = new MitreAttackFramework();
		mitre.downloadData();
	}
}
