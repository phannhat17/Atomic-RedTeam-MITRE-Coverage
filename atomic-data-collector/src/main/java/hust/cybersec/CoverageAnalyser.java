package hust.cybersec;

public class CoverageAnalyser
{
	private AtomicRedTeam atomic;
	private MitreAttackFramework mitre;

	public CoverageAnalyser(AtomicRedTeam atomic, MitreAttackFramework mitre)
	{
		this.atomic = atomic;
		this.mitre = mitre;
	}

	public void analyse()
	{
		preprocessData();
		double ratio = calculateCoverageRatio();
		
		generateChart();
	}
	
	private void preprocessData()
	{
		buildDataTree();
	}
	
	private void buildDataTree()
	{
		
	}
	
	private double calculateCoverageRatio()
	{
		return 0.0;
	}

	private void generateChart()
	{

	}
}
