package hust.cybersec.data.process.structure;

import java.util.Arrays;

/**
 * Represents a tree structure for storing and retrieving data nodes.
 */
public class DataTree {
    private final DataNode root;

    /**
     * Constructs a DataTree with the specified domain as the root node.
     * The tree is built by initializing the root node and its child nodes.
     *
     * @param domain The domain for the root node of the tree.
     */
    public DataTree(String domain) {
        root = new DataNode(domain, new Triple(0, new Pair(0, 0)));
        buildTree(root);
    }

    /**
     * Builds the data tree by initializing the child nodes for each tactic and platform.
     *
     * @param parentNode The parent node for building the child nodes.
     */
    private void buildTree(DataNode parentNode) {
        for (String tactic : Constants.TACTICS) {
            DataNode tacticNode = new DataNode(tactic, new Triple(0, new Pair(0, 0)));
            parentNode.getChild().put(tactic, tacticNode);

            for (String platform : Constants.PLATFORMS) {
                DataNode platformNode = new DataNode(platform, new Triple(0, new Pair(0, 0)));
                tacticNode.getChild().put(platform, platformNode);

                DataNode atomicTechniqueNode = new DataNode("Atomic.Total", new Pair(0, 0));
                platformNode.getChild().put("Atomic.Total", atomicTechniqueNode);

                DataNode mitreTechniqueNode = new DataNode("Mitre.Total", 0);
                platformNode.getChild().put("Mitre.Total", mitreTechniqueNode);
            }
        }
    }

    /**
     * Retrieves the value of the node at the specified path in the data tree.
     *
     * @param path The path to the node.
     * @return The value of the node, or null if the node is not found.
     */
    public Object getValue(String[] path) {
        DataNode node = getNode(path);
        return (node != null) ? node.getValue() : null;
    }

    /**
     * Sets the value of the node at the specified path in the data tree.
     *
     * @param path  The path to the node.
     * @param value The value to set for the node.
     */
    public void setValue(String[] path, Object value) {
        DataNode node = getNode(path);
        if (node != null) {
            node.setValue(value);
        }
    }

    /**
     * Retrieves the data node at the specified path in the data tree.
     *
     * @param path The path to the node.
     * @return The data node, or null if the node is not found.
     */
    private DataNode getNode(String[] path) {
        DataNode current = root;
        for (int i = 1; i < path.length; ++i) {
            String level = path[i];
            if (path[i] == null) {
                break;
            }
            current = current.getChild().get(level);
            if (current == null) {
                System.out.println("Path not found: " + Arrays.toString(path));
                return null;
            }
        }
        return current;
    }
}
