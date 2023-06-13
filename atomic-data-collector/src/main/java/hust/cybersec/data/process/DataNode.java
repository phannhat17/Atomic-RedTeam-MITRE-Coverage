package hust.cybersec.data.process;

import java.util.*;

public class DataNode
{
	private String name;
	private int value;
	private Map<String, DataNode> child;

	public DataNode(String name)
	{
		this.name = name;
		this.value = 0;
		this.child = new HashMap<>();
	}

	public DataNode(String name, int value)
	{
		this.name = name;
		this.value = value;
		this.child = new HashMap<>();
	}

	public DataNode(String name, int value, Map<String, DataNode> child)
	{
		this.name = name;
		this.value = value;
		this.child = child;
	}

	public int getValue()
	{
		return value;
	}

	public void setValue(int value)
	{
		this.value = value;
	}

	public String getName()
	{
		return name;
	}

	public Map<String, DataNode> getChild()
	{
		return child;
	}
}
