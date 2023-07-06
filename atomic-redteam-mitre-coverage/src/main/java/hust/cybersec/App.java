package hust.cybersec;

import hust.cybersec.data.model.AtomicRedTeam;
import hust.cybersec.data.model.MitreAttackFramework;

import java.io.IOException;
import java.net.URISyntaxException;

public class App
{
	static MitreAttackFramework mitre = new MitreAttackFramework();
	static AtomicRedTeam atomic = new AtomicRedTeam();

	public static void main(String[] args) throws URISyntaxException, IOException
	{
//		mitre.downloadData();
//		atomic.downloadData();
//		atomic.exportExcel();
		atomic.analyseCoverage();
	}
}
