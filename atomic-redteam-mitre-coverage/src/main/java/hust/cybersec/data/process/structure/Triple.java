package hust.cybersec.data.process.structure;

/**
 * Represents a triple of values used in the data structure.
 * Stores the values for the MITRE node and the atomic node (which consists of a Pair object).
 */

public class Triple {
    private Integer mitreNode;
    private Pair atomicNode;

    /**
     * Constructs a Triple object with the specified values for the MITRE node and atomic node.
     *
     * @param mitreNode  The value for the MITRE node.
     * @param atomicNode The Pair object representing the atomic node.
     */
    public Triple(Integer mitreNode, Pair atomicNode) {
        this.mitreNode = mitreNode;
        this.atomicNode = atomicNode;
    }

    /**
     * Retrieves the value for the MITRE node.
     *
     * @return The value for the MITRE node.
     */
    public Integer getMitreNode() {
        return mitreNode;
    }

    /**
     * Sets the value for the MITRE node.
     *
     * @param mitreNode The value to set for the MITRE node.
     */
    public void setMitreNode(Integer mitreNode) {
        this.mitreNode = mitreNode;
    }

    /**
     * Retrieves the Pair object representing the atomic node.
     *
     * @return The Pair object representing the atomic node.
     */
    public Pair getAtomicNode() {
        return atomicNode;
    }

    /**
     * Sets the Pair object representing the atomic node.
     *
     * @param atomicNode The Pair object to set for the atomic node.
     */
    public void setAtomicNode(Pair atomicNode) {
        this.atomicNode = atomicNode;
    }
}
