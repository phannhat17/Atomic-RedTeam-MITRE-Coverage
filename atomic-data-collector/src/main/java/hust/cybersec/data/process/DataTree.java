package hust.cybersec.data.process;

import java.util.Arrays;

public class DataTree
{
	private DataNode root;

	public DataTree(String domain)
	{
		root = new DataNode(domain, new Pair(0, 0));
		buildTree(root);
	}

	private void buildTree(DataNode parentNode)
	{
		for (String tactic : Constants.TACTICS)
		{
			DataNode tacticNode = new DataNode(tactic, new Pair(0, 0));
			parentNode.getChild().put(tactic, tacticNode);

			for (String platform : Constants.PLATFORMS)
			{
				DataNode platformNode = new DataNode(platform, new Pair(0, 0));
				tacticNode.getChild().put(platform, platformNode);

				DataNode atomicTechniqueNode = new DataNode("Atomic.Technique", 0);
				platformNode.getChild().put("Atomic.Technique", atomicTechniqueNode);

				DataNode atomicTestNode = new DataNode("Atomic.Test", 0);
				atomicTechniqueNode.getChild().put("Atomic.Test", atomicTestNode);

				DataNode mitreTechniqueNode = new DataNode("Mitre.Technique", 0);
				platformNode.getChild().put("Mitre.Technique", mitreTechniqueNode);
			}
		}
	}

	public Object getValue(String[] path)
	{
		DataNode node = getNode(path);
		return (node != null) ? node.getValue() : null;
	}

	public void setValue(String[] path, Object value)
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
				System.out.println("Path not found: " + Arrays.toString(path));
				return null;
			}
		}
		return current;
	}

//	public static void main(String[] args)
//	{
//		DataTree dataTree = new DataTree("enterprise");
//
//		// Retrieve node values
//		Integer value = dataTree.getValue(new String[] { "enterprise", "collection", "macOS", "Mitre.Technique" });
//		System.out.println("Value: " + value);
//		value = dataTree.getValue(new String[] { "enterprise", "collection" });
//		System.out.println("Value: " + value);
//
//		// Set node value
//		dataTree.setValue(new String[] { "enterprise", "collection", "macOS", "Mitre.Technique" }, 10);
//		dataTree.setValue(new String[] { "enterprise", "collection" }, 10);
//
//		// Retrieve updated node value
//		value = dataTree.getValue(new String[] { "enterprise", "collection", "macOS", "Mitre.Technique" });
//		System.out.println("Updated value: " + value);
//		value = dataTree.getValue(new String[] { "enterprise", "collection" });
//		System.out.println("Updated value: " + value);
//	}
}