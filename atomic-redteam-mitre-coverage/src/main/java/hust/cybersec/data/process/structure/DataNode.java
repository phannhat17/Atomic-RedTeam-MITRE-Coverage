package hust.cybersec.data.process.structure;

import java.util.HashMap;
import java.util.Map;

public class DataNode {
    private final String name;
    private Object value;
    private final Map<String, DataNode> child;

    /**
     * Constructs a DataNode with the specified name and initializes the child map.
     *
     * @param name The name of the DataNode.
     */
    public DataNode(String name) {
        this.name = name;
        this.child = new HashMap<>();
    }

    /**
     * Constructs a DataNode with the specified name, value, and initializes the child map.
     * The value can only be an instance of Pair, Integer, or Triple.
     *
     * @param name  The name of the DataNode.
     * @param value The value associated with the DataNode.
     */
    public DataNode(String name, Object value) {
        this.name = name;
        if (value instanceof Pair || value instanceof Integer || value instanceof Triple) {
            this.value = value;
        }
        this.child = new HashMap<>();
    }

    /**
     * Constructs a DataNode with the specified name, value, and child nodes.
     *
     * @param name  The name of the DataNode.
     * @param value The value associated with the DataNode.
     * @param child The child nodes of the DataNode.
     */
    public DataNode(String name, Object value, Map<String, DataNode> child) {
        this.name = name;
        this.value = value;
        this.child = child;
    }

    /**
     * Checks if the DataNode has a value associated with it.
     *
     * @return true if the DataNode has a value, false otherwise.
     */
    public boolean hasValue() {
        return value != null;
    }

    /**
     * Retrieves the value associated with the DataNode.
     *
     * @return The value associated with the DataNode.
     */
    public Object getValue() {
        return value;
    }

    /**
     * Sets the value associated with the DataNode.
     * Only allows setting a value if the DataNode has a value and the provided value is of type Pair, Integer, or Triple.
     *
     * @param value The value to be set for the DataNode.
     */
    public void setValue(Object value) {
        if (!this.hasValue()) {
            System.out.println("Cannot set value for this node");
            return;
        }
        if (!(value instanceof Pair || value instanceof Integer || value instanceof Triple)) {
            System.out.println("Cannot set the value with this type");
            return;
        }
        this.value = value;
    }

    /**
     * Retrieves the name of the DataNode.
     *
     * @return The name of the DataNode.
     */
    public String getName() {
        return name;
    }

    /**
     * Retrieves the child nodes of the DataNode.
     *
     * @return The child nodes of the DataNode.
     */
    public Map<String, DataNode> getChild() {
        return child;
    }
}
