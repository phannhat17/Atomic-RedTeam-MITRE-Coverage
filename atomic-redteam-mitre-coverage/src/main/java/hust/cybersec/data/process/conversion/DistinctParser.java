package hust.cybersec.data.process.conversion;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import hust.cybersec.data.process.structure.Constants;
import hust.cybersec.data.process.validation.JsonNodeHandler;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashSet;

public class DistinctParser {
    private final HashSet<String> tacticList = new HashSet<>();
    private final HashSet<String> platformList = new HashSet<>();

    private final JsonNodeHandler jsonHandler = new JsonNodeHandler();

    private void getTacticList(JsonNode root, String domain) {
        if (root.has("kill_chain_phases")) {
            root = root.get("kill_chain_phases");
            if (root != null && root.isArray()) {
                for (JsonNode phaseNode : root) {
                    if (phaseNode.has("kill_chain_name") && phaseNode.has("phase_name")) {
                        if (phaseNode.get("kill_chain_name").asText().equals(domain)) {
                            tacticList.add(phaseNode.get("phase_name").asText().toLowerCase());
                        }
                    }
                }
            }
        }
    }

    private void getPlatformList(JsonNode root) {
        if (root.has("x_mitre_platforms")) {
            root = root.get("x_mitre_platforms");
            if (root != null && root.isArray()) {
                for (JsonNode valueNode : root) {
                    platformList.add(valueNode.asText().toLowerCase());
                }
            }
        }
    }

    private void parseData() {
        String JSON_DIRECTORY_PATH = "./data/mitre-attack/";
        for (int i = 0; i < Constants.DOMAINS.length; ++i) {
            String domain = Constants.DOMAINS[i];
            try {
                String jsonData = new String(Files.readAllBytes(Paths.get(JSON_DIRECTORY_PATH + domain + ".json")));
                ObjectMapper objectMapper = new ObjectMapper();
                JsonNode rootData = objectMapper.readTree(jsonData);
                rootData = rootData.get("objects");
                if (rootData != null && rootData.isArray()) {
                    for (JsonNode techniqueNode : rootData) {
                        if (jsonHandler.checkValid(techniqueNode)) {
                            getTacticList(techniqueNode, Constants.KILL_CHAIN_NAME[i]);
                            if (techniqueNode.has("x_mitre_platforms")) {
                                getPlatformList(techniqueNode);
                            }
                        }
                    }
                }
            } catch (IOException e) {
                System.err.println("Path not found!");
            }
        }
    }

    public String[] parseDistinctTactic() {
        if (tacticList.isEmpty()) {
            parseData();
        }
        return tacticList.toArray(new String[0]);
    }

    public String[] parseDistinctPlatform() {
        if (platformList.isEmpty()) {
            parseData();
        }
        return platformList.toArray(new String[0]);
    }
}
