package hust.cybersec.data.process;

public class Pair
{
	private Integer atomicTechnique;
	private Integer atomicTest;

	public Pair(Integer atomicTechnique, Integer atomicTest)
	{
		this.atomicTechnique = atomicTechnique;
		this.atomicTest = atomicTest;
	}

	public Integer getAtomicTechnique()
	{
		return atomicTechnique;
	}

	public void setAtomicTechnique(Integer atomicTechnique)
	{
		this.atomicTechnique = atomicTechnique;
	}

	public Integer getAtomicTest()
	{
		return atomicTest;
	}

	public void setAtomicTest(Integer atomicTest)
	{
		this.atomicTest = atomicTest;
	}
}
