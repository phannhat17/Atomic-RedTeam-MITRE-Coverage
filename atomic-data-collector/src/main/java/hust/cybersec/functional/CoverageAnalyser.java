package hust.cybersec.functional;

import hust.cybersec.data.model.AtomicRedTeam;
import hust.cybersec.data.model.MitreAttackFramework;

public class CoverageAnalyser
{
	private AtomicRedTeam atomic;
	private MitreAttackFramework mitre;

	public CoverageAnalyser(AtomicRedTeam atomic, MitreAttackFramework mitre)
	{
		this.atomic = atomic;
		this.mitre = mitre;
	}

	private double calculateCoverageRatio()
	{
		return 0.0;
	}

	public void generateChart()
	{

	}
}
