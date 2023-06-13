package com.example;

public class DataTree
{
	private DataNode root;
	private static final String[] tacticList = { "reconnaissance", "resource-development", "initial-access",
			"execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access", "discovery",
			"lateral-movement", "collection", "command-and-control", "exfiltration", "impact" };
	private static final String[] platformList = { "Windows", "Azure AD", "Office 365", "SaaS", "IaaS", "Linux",
			"macOS", "Google Workspace", "Containers", "Network" };

	public DataTree(String domains)
	{
		root = new DataNode(domains, 0);
		buildTree(root);
	}

	private void buildTree(DataNode parentNode)
	{
		for (String tactic : tacticList)
		{
			DataNode tacticNode = new DataNode(tactic);
			parentNode.getChild().put(tactic, tacticNode);

			for (String platform : platformList)
			{
				DataNode platformNode = new DataNode(platform);
				tacticNode.getChild().put(platform, platformNode);

				DataNode totalTechniqueNode = new DataNode("TOTAL.Technique");
				platformNode.getChild().put("TOTAL.Technique", totalTechniqueNode);

				for (String testPlatform : platformList)
				{
					DataNode testPlatformNode = new DataNode(testPlatform);
					platformNode.getChild().put(testPlatform, testPlatformNode);
				}
			}
		}
	}

	public int getValue(String[] path)
	{
		DataNode node = getNode(path);
		return (node != null) ? node.getValue() : 0;
	}

	public void setValue(String[] path, int value)
	{
		DataNode node = getNode(path);
		if (node != null)
		{
			node.setValue(value);
		}
	}

	private DataNode getNode(String[] path)
	{
		DataNode current = root;
		for (int i = 1; i < path.length; ++i)
		{
			String level = path[i];
			current = current.getChild().get(level);
			if (current == null)
			{
				System.out.println("Path not found!");
				return null;
			}
		}
		return current;
	}

	public static void main(String[] args)
	{
		DataTree dataTree = new DataTree("enterprise");

		// Retrieve node values
		int value = dataTree.getValue(new String[] { "enterprise", "collection", "macOS" });
		System.out.println("Value: " + value);

		// Set node value
		dataTree.setValue(new String[] { "enterprise", "collection", "macOS" }, 10);

		// Retrieve updated node value
		value = dataTree.getValue(new String[] { "enterprise", "collection", "macOS" });
		System.out.println("Updated value: " + value);
	}
}
