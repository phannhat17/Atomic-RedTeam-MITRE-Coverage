package hust.cybersec.data.process;

public class Triple
{
	private Integer mitreNode;
	private Pair atomicNode;

	public Triple(Integer mitreNode, Pair atomicNode)
	{
		this.mitreNode = mitreNode;
		this.atomicNode = atomicNode;
	}

	public Integer getMitreNode()
	{
		return mitreNode;
	}

	public void setMitreNode(Integer mitreNode)
	{
		this.mitreNode = mitreNode;
	}

	public Pair getAtomicNode()
	{
		return atomicNode;
	}

	public void setAtomicNode(Pair atomicNode)
	{
		this.atomicNode = atomicNode;
	}
}
