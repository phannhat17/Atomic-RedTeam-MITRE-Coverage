package hust.cybersec.data.process;

public class Constants
{
	public static final String[] DOMAINS = { "enterprise-attack", "mobile-attack", "ics-attack" };

	public static final String[] KILL_CHAIN_NAME = { "mitre-attack", "mitre-mobile-attack", "mitre-ics-attack" };

	private static DistinctParser parser = new DistinctParser();

	public static final String[] TACTICS = parser.parseDistinctTactic();

	public static final String[] PLATFORMS = parser.parseDistinctPlatform();
}
