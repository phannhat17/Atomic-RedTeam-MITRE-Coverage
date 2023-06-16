package hust.cybersec.data.process;

public class Pair
{
	private Integer firstPairElement;
	private Integer secondPairElement;

	public Pair(Integer firstPairElement, Integer secondPairElement)
	{
		this.firstPairElement = firstPairElement;
		this.secondPairElement = secondPairElement;
	}

	public Integer getFirstPairElement()
	{
		return firstPairElement;
	}

	public void setFirstPairElement(Integer firstPairElement)
	{
		this.firstPairElement = firstPairElement;
	}

	public Integer getSecondPairElement()
	{
		return secondPairElement;
	}

	public void setSecondPairElement(Integer secondPairElement)
	{
		this.secondPairElement = secondPairElement;
	}
}
