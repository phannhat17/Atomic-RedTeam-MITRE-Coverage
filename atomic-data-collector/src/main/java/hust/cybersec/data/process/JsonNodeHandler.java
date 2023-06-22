package hust.cybersec.data.process;

import com.fasterxml.jackson.databind.JsonNode;

public class JsonNodeHandler {
    public String getNodeValue(JsonNode node, String fieldName) {
        if (node.has(fieldName)) {
            return node.get(fieldName).asText();
        }
        return "";
    }

    public boolean checkValid(JsonNode root) {
        if (!getNodeValue(root, "type").equals("attack-pattern")) {
            return false;
        }
        if (getNodeValue(root, "revoked").equals("true")) {
            return false;
        }
        if (getNodeValue(root, "x_mitre_deprecated").equals("true")) {
            return false;
        }
        if (!root.has("external_references")) {
            return false;
        }
        JsonNode externalReferencesNode = root.get("external_references");
        JsonNode externalNode = null;
        if (externalReferencesNode != null && externalReferencesNode.isArray()) {
            for (JsonNode referenceNode : externalReferencesNode) {
                if (referenceNode.has("external_id")
                        && referenceNode.get("source_name").asText().equals("mitre-attack")) {
                    if (referenceNode.get("external_id").asText().startsWith("T")) {
                        externalNode = referenceNode;
                        break;
                    }
                }
            }
        }
        return externalNode != null;
    }
}
