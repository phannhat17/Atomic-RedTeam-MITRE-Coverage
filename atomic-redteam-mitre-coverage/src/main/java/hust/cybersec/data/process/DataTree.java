package hust.cybersec.data.process;

import java.util.Arrays;

public class DataTree {
    private final DataNode root;

    public DataTree(String domain) {
        root = new DataNode(domain, new Triple(0, new Pair(0, 0)));
        buildTree(root);
    }

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

    public Object getValue(String[] path) {
        DataNode node = getNode(path);
        return (node != null) ? node.getValue() : null;
    }

    public void setValue(String[] path, Object value) {
        DataNode node = getNode(path);
        if (node != null) {
            node.setValue(value);
        }
    }

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
