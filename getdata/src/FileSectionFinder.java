import java.io.*;

public class FileSectionFinder {
    public static void main(String[] args) {
        // Specify the input file path
        String inputFile = "./atomic/atomic-all.yaml";
        // Specify the output file path
        
        // Specify the starting and ending markers for the section
        
        String[][] tacticsList =  {
            {"defense-evasion:", "privilege-escalation:"},
            {"privilege-escalation:", "execution:"},
            {"execution:", "persistence:"},
            {"persistence:", "command-and-control:"},
            {"command-and-control:", "collection:"},
            {"collection:", "lateral-movement:"},
            {"lateral-movement:", "credential-access:"},
            {"credential-access:", "discovery:"},
            {"discovery:", "resource-development:"},
            {"resource-development:", "reconnaissance:"},
            {"reconnaissance:", "impact:"},
            {"impact:", "initial-access:"},
            {"initial-access:", "exfiltration:"}
        };
        for (String[] tacs : tacticsList) {
            String nameFile = tacs[0].split(":")[0];
            String outputPath = "./atomic/" + nameFile + "/" ;
            File directory = new File(outputPath);
            if (!directory.exists()) {
                directory.mkdirs();
            }
            String outputFile = outputPath + "/" + nameFile + ".yaml";
            String startMarker = tacs[0] ;
            String endMarker = tacs[1];
            try (BufferedReader reader = new BufferedReader(new FileReader(inputFile));
                BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {
                String line;
                boolean inSection = false;

                while ((line = reader.readLine()) != null) {
                    if (!inSection && line.contains(startMarker)) {
                        inSection = true;
                        writer.write(line);
                        writer.newLine();
                    } else if (inSection) {
                        if (!line.contains(endMarker)) {
                            writer.write(line);
                            writer.newLine();
                        } else {
                            break;
                        }
                    }
                }

                System.out.println("Section extraction completed successfully.");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

       
    }
}
