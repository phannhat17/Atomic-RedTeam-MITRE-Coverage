package hust.cybersec.data.process;

public class Triple
{
	private Integer firstTripleElement;
	private Pair secondThirdElement;

	public Triple(Integer firstTripleElement, Pair secondThirdElement)
	{
		this.firstTripleElement = firstTripleElement;
		this.secondThirdElement = secondThirdElement;
	}

	public Integer getFirstTripleElement()
	{
		return firstTripleElement;
	}

	public void setFirstTripleElement(Integer firstTripleElement)
	{
		this.firstTripleElement = firstTripleElement;
	}

	public Pair getSecondThirdElement()
	{
		return secondThirdElement;
	}

	public void setSecondThirdElement(Pair secondThirdElement)
	{
		this.secondThirdElement = secondThirdElement;
	}
}
