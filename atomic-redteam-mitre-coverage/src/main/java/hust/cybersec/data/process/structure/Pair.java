package hust.cybersec.data.process.structure;

/**
 * Represents a pair of integers used in the data structure.
 * stores the values for atomic technique and atomic test.
 */
public class Pair {
    private Integer atomicTechnique;
    private Integer atomicTest;

    /**
     * Constructs a Pair object with the specified values for atomic technique and atomic test.
     *
     * @param atomicTechnique The value for atomic technique.
     * @param atomicTest      The value for atomic test.
     */
    public Pair(Integer atomicTechnique, Integer atomicTest) {
        this.atomicTechnique = atomicTechnique;
        this.atomicTest = atomicTest;
    }

    /**
     * Retrieves the value for atomic technique.
     *
     * @return The value for atomic technique.
     */
    public Integer getAtomicTechnique() {
        return atomicTechnique;
    }

    /**
     * Sets the value for atomic technique.
     *
     * @param atomicTechnique The value to set for atomic technique.
     */
    public void setAtomicTechnique(Integer atomicTechnique) {
        this.atomicTechnique = atomicTechnique;
    }

    /**
     * Retrieves the value for atomic test.
     *
     * @return The value for atomic test.
     */
    public Integer getAtomicTest() {
        return atomicTest;
    }

    /**
     * Sets the value for atomic test.
     *
     * @param atomicTest The value to set for atomic test.
     */
    public void setAtomicTest(Integer atomicTest) {
        this.atomicTest = atomicTest;
    }
}
