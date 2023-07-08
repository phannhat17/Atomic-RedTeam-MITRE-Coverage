package hust.cybersec.data.process.validation;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Provides methods for handling and validating JsonNode objects.
 */
public class JsonNodeHandler {

    /**
     * Retrieves the value of the specified field from the JsonNode as a string.
     *
     * @param node      The JsonNode object.
     * @param fieldName The name of the field.
     * @return The value of the field as a string, or an empty string if the field is not found.
     */
    public String getNodeValue(JsonNode node, String fieldName) {
        if (node.has(fieldName)) {
            return node.get(fieldName).asText();
        }
        return "";
    }

    /**
     * Checks if the given JsonNode represents a valid attack pattern based on specific criteria.
     *
     * @param root The root JsonNode object to validate.
     * @return true if the JsonNode is valid, false otherwise.
     */
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
                if (referenceNode.has("external_id") && referenceNode.get("source_name").asText()
                        .equals("mitre-attack")) {
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
