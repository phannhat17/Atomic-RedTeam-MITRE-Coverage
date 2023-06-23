package hust.cybersec.data.process;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import hust.cybersec.data.model.AtomicRedTeam;
import hust.cybersec.data.model.MitreAttackFramework;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class Deserializer extends JsonDeserializer<Object> {
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final JsonNodeHandler jsonHandler = new JsonNodeHandler();

    @Override
    public Object deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
        JsonNode node = jsonParser.getCodec().readTree(jsonParser);

        if (node.has("auto_generated_guid")) {
            return deserializeAtomicRedTeam(node);
        } else {
            return deserializeMitreAttackFramework(node);
        }
    }

    private JsonNode findExternalNode(JsonNode externalReferencesNode) {
        JsonNode externalNode = null;
        if (externalReferencesNode != null && externalReferencesNode.isArray()) {
            for (JsonNode referenceNode : externalReferencesNode) {
                if (referenceNode.has("external_id")
                        && referenceNode.get("source_name").asText().equals("mitre-attack")) {
                    externalNode = referenceNode;
                    break;
                }
            }
        }
        return externalNode;
    }

    private String[] parseStringArray(ObjectMapper objectMapper, JsonNode node, String fieldName)
            throws JsonProcessingException, IllegalArgumentException {
        if (node.has(fieldName)) {
            return objectMapper.treeToValue(node.get(fieldName), String[].class);
        }
        return new String[0];
    }

    private String[] parseTactics(JsonNode node) {
        if (!node.has("kill_chain_phases")) {
            return new String[0];
        }
        JsonNode jsonNode = node.get("kill_chain_phases");
        List<String> phaseNames = new ArrayList<>();
        if (jsonNode != null && jsonNode.isArray()) {
            for (JsonNode phaseNode : jsonNode) {
                if (phaseNode.has("phase_name")) {
                    String phaseName = phaseNode.get("phase_name").asText();
                    phaseNames.add(phaseName);
                }
            }
        }
        return phaseNames.toArray(new String[0]);
    }

    private String[] parseInputArguments(JsonNode node) {
        if (!node.has("input_arguments")) {
            return new String[0];
        }
        JsonNode jsonNode = node.get("input_arguments");
        List<String> inputArgumentsList = new ArrayList<>();
        if (jsonNode != null && jsonNode.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> argumentFields = jsonNode.fields();
            while (argumentFields.hasNext()) {
                Map.Entry<String, JsonNode> argumentField = argumentFields.next();
                StringBuilder combinedValues = new StringBuilder();
                String nodeName = argumentField.getKey();
                combinedValues.append("* ").append(nodeName).append(":\n        ");
                JsonNode subNode = argumentField.getValue();
                Iterator<Map.Entry<String, JsonNode>> subNodeFileds = subNode.fields();
                while (subNodeFileds.hasNext()) {
                    Map.Entry<String, JsonNode> subNodeField = subNodeFileds.next();
                    String subNodeName = subNodeField.getKey();
                    JsonNode subNodeValue = subNodeField.getValue();
                    if (subNodeValue != null) {
                        combinedValues.append(subNodeName).append(": ").append(subNodeValue).append("\n        ");
                    }
                }
                inputArgumentsList.add(combinedValues.toString());
            }
        }
        return inputArgumentsList.toArray(new String[0]);
    }

    private String[] parseExecutor(JsonNode node) {
        if (!node.has("executor")) {
            return new String[0];
        }
        JsonNode jsonNode = node.get("executor");
        List<String> executorList = new ArrayList<>();
        if (jsonNode != null && jsonNode.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> executorFields = jsonNode.fields();
            while (executorFields.hasNext()) {
                Map.Entry<String, JsonNode> executorField = executorFields.next();
                StringBuilder combinedValues = new StringBuilder();
                String nodeName = executorField.getKey();
                combinedValues.append("* ").append(nodeName).append(": ");
                JsonNode nodeValue = executorField.getValue();
                if (nodeValue != null) {
                    combinedValues.append(nodeValue);
                }
                executorList.add(combinedValues.toString());
            }
        }
        return executorList.toArray(new String[0]);
    }

    private String[] parseDependencies(JsonNode node) {
        if (!node.has("dependencies")) {
            return new String[0];
        }
        JsonNode jsonNode = node.get("dependencies");
        List<String> dependenciesList = new ArrayList<>();
        if (jsonNode != null && jsonNode.isArray()) {
            for (JsonNode dependencyNode : jsonNode) {
                Iterator<Map.Entry<String, JsonNode>> dependencyFields = dependencyNode.fields();
                while (dependencyFields.hasNext()) {
                    Map.Entry<String, JsonNode> dependencyField = dependencyFields.next();
                    StringBuilder combinedValues = new StringBuilder();
                    String nodeName = dependencyField.getKey();
                    JsonNode nodeValue = dependencyField.getValue();
                    if (nodeValue != null) {
                        combinedValues.append("* ").append(nodeName).append(": ").append(nodeValue);
                    }
                    dependenciesList.add(combinedValues.toString());
                }
                dependenciesList.add("\n");
            }
        }
        return dependenciesList.toArray(new String[0]);
    }

    private MitreAttackFramework deserializeMitreAttackFramework(JsonNode node)
            throws JsonProcessingException, IllegalArgumentException {

        JsonNode externalReferencesNode = node.has("external_references") ? node.get("external_references") : null;
        JsonNode externalNode = findExternalNode(externalReferencesNode);
        String techniqueId = (externalNode != null && externalNode.has("external_id"))
                ? externalNode.get("external_id").asText()
                : "";

        String techniqueName = jsonHandler.getNodeValue(node, "name");

        String techniqueDescription = jsonHandler.getNodeValue(node, "description");

        String[] techniquePlatforms = parseStringArray(objectMapper, node, "x_mitre_platforms");

        String[] techniqueDomains = parseStringArray(objectMapper, node, "x_mitre_domains");

        String techniqueUrl = (externalNode != null && externalNode.has("url")) ? externalNode.get("url").asText() : "";

        String[] techniqueTactics = parseTactics(node);

        String techniqueDetection = jsonHandler.getNodeValue(node, "x_mitre_detection");

        boolean techniqueIsSubtechnique = node.has("x_mitre_is_subtechnique")
                && node.get("x_mitre_is_subtechnique").asBoolean();

        return new MitreAttackFramework(techniqueId, techniqueName, techniqueDescription, techniquePlatforms,
                techniqueDomains, techniqueUrl, techniqueTactics, techniqueDetection, techniqueIsSubtechnique);
    }

    private AtomicRedTeam deserializeAtomicRedTeam(JsonNode node)
            throws JsonProcessingException, IllegalArgumentException {
        String testName = jsonHandler.getNodeValue(node, "name");

        String testGuid = jsonHandler.getNodeValue(node, "auto_generated_guid");

        String testDescription = jsonHandler.getNodeValue(node, "description");

        String[] testSupportedPlatforms = parseStringArray(objectMapper, node, "supported_platforms");

        String[] testInputArguments = parseInputArguments(node);

        String[] testExecutor = parseExecutor(node);

        String testDependencyExecutorName = jsonHandler.getNodeValue(node, "dependency_executor_name");

        String[] testDependencies = parseDependencies(node);

        return new AtomicRedTeam(testName, testGuid, testDescription, testSupportedPlatforms, testInputArguments,
                testExecutor, testDependencyExecutorName, testDependencies);
    }
}
