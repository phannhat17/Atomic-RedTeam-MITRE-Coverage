package hust.cybersec.data.process;

public class Pair
{
	private Integer first_mitre;
	private Integer second_atomic;

	public Pair(Integer first_mitre, Integer second_atomic)
	{
		this.first_mitre = first_mitre;
		this.second_atomic = second_atomic;
	}

	public Integer getFirst_mitre()
	{
		return first_mitre;
	}

	public void setFirst_mitre(Integer first_mitre)
	{
		this.first_mitre = first_mitre;
	}

	public Integer getSecond_atomic()
	{
		return second_atomic;
	}

	public void setSecond_atomic(Integer second_atomic)
	{
		this.second_atomic = second_atomic;
	}

}
