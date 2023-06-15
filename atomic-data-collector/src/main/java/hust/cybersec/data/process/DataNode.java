package hust.cybersec.data.process;

import java.util.*;

public class DataNode
{
	private String name;
	private Object value;
	private Map<String, DataNode> child;

	public DataNode(String name)
	{
		this.name = name;
		this.child = new HashMap<>();
	}

	public DataNode(String name, Object value)
	{
		this.name = name;
		if (value instanceof Pair || value instanceof Integer)
		{
			this.value = value;
		}
		this.child = new HashMap<>();
	}

	public DataNode(String name, Object value, Map<String, DataNode> child)
	{
		this.name = name;
		this.value = value;
		this.child = child;
	}

	public boolean hasValue()
	{
		return value != null;
	}

	public Object getValue()
	{
		return value;
	}

	public void setValue(Object value)
	{
		if (!this.hasValue())
		{
			System.out.println("Cannot set value for this node");
			return;
		}
		if (!(value instanceof Pair || value instanceof Integer))
		{
			System.out.println("Cannot set the value with this type");
			return;
		}
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
