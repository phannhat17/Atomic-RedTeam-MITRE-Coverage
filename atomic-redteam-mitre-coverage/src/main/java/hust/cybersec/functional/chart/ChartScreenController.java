package hust.cybersec.functional.chart;

import hust.cybersec.data.process.conversion.JsonToTreeProcessor;
import hust.cybersec.data.process.structure.Constants;
import hust.cybersec.data.process.structure.DataTree;
import hust.cybersec.data.process.structure.Pair;
import hust.cybersec.data.process.structure.Triple;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.embed.swing.SwingFXUtils;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.chart.CategoryAxis;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.StackedBarChart;
import javafx.scene.chart.XYChart;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.Label;
import javafx.scene.control.Tooltip;
import javafx.scene.image.WritableImage;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.BorderPane;
import javafx.util.Duration;

import javax.imageio.ImageIO;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;

public class ChartScreenController {
    @FXML
    private Label analyseResult;

    @FXML
    private StackedBarChart<String, Number> chart;

    @FXML
    private ChoiceBox<String> firstChoiceBox;

    @FXML
    private ChoiceBox<String> secondChoiceBox;

    @FXML
    private ChoiceBox<String> thirdChoiceBox;

    @FXML
    private CategoryAxis xAxis;

    @FXML
    private NumberAxis yAxis;

    @FXML
    private BorderPane screenBorder;

    // Series for covered and uncovered data
    private final XYChart.Series<String, Number> coveredSeries = new XYChart.Series<>();

    private final XYChart.Series<String, Number> uncoveredSeries = new XYChart.Series<>();

    // Observable lists for choice boxes
    private final ObservableList<String> PLATFORMS = FXCollections.observableArrayList(Constants.PLATFORMS);
    private final ObservableList<String> TACTICS = FXCollections.observableArrayList(Constants.TACTICS);
    private final ObservableList<String> DOMAINS = FXCollections.observableArrayList(Constants.DOMAINS);
    private final ObservableList<String> TAXONOMIES = FXCollections.observableArrayList("domain", "tactic", "platform");
    private final String ALL = "---------- ALL ------------";

    private final String COVERED = "Covered";
    private final String UNCOVERED = "Uncovered";

    private final JsonToTreeProcessor processor = new JsonToTreeProcessor();

    // Initialize DOMAINS, TACTICS, and PLATFORMS with "ALL" option and build data tree
    {
        DOMAINS.add(ALL);
        TACTICS.add(ALL);
        PLATFORMS.add(ALL);
        processor.buildDataTree();
        coveredSeries.setName(COVERED);
        uncoveredSeries.setName(UNCOVERED);
    }

    // Data trees for different domains
    private final DataTree ENTERPRISE_TREE = processor.getEnterpriseTree();
    private final DataTree MOBILE_TREE = processor.getMobileTree();
    private final DataTree ICS_TREE = processor.getIcsTree();

    // Path for tree traversal
    private final String[] path = new String[4];
    private final String MITRE_TOTAL = "Mitre.Total";
    private final String ATOMIC_TOTAL = "Atomic.Total";

    private DataTree selectedTree; // Selected data tree for traversal

    private Triple tripleValue; // Value of the current tree node

    private String selectedTaxonomyString = ""; // Selected taxonomy string

    /**
     * Sets up the initial stage by populating the choice boxes and triggering the analysis.
     */
    public void firstStage() {
        // Set for initial stage
        ObservableList<String> firstChoices = FXCollections.observableArrayList(TAXONOMIES);
        firstChoiceBox.setItems(firstChoices.sorted());
        firstChoiceBox.getSelectionModel().select(TAXONOMIES.get(0));

        String selectedFirstChoice = firstChoiceBox.getSelectionModel().getSelectedItem();
        setChoiceBoxes(selectedFirstChoice);
        analyseButtonPressed(new ActionEvent());
    }

    /**
     * Sets the choice boxes based on the selected taxonomy.
     *
     * @param selectedFirstChoice The selected taxonomy.
     */
    public void setChoiceBoxes(String selectedFirstChoice) {
        if (selectedFirstChoice.equals(TAXONOMIES.get(0))) {
            secondChoiceBox.setItems(DOMAINS.sorted());
            thirdChoiceBox.setItems(FXCollections.observableArrayList(TAXONOMIES.get(1), TAXONOMIES.get(2)));
        } else if (selectedFirstChoice.equals(TAXONOMIES.get(1))) {
            secondChoiceBox.setItems(TACTICS.sorted());
            thirdChoiceBox.setItems(FXCollections.observableArrayList(TAXONOMIES.get(0), TAXONOMIES.get(2)));
        } else if (selectedFirstChoice.equals(TAXONOMIES.get(2))) {
            secondChoiceBox.setItems(PLATFORMS.sorted());
            thirdChoiceBox.setItems(FXCollections.observableArrayList(TAXONOMIES.get(1), TAXONOMIES.get(0)));
        }
        secondChoiceBox.getSelectionModel().select(ALL);
        thirdChoiceBox.getSelectionModel().selectFirst();
    }

    /**
     * Adds data to the chart for the specified category.
     *
     * @param category        The category to add data for.
     * @param atomicTechnique The number of atomic techniques.
     * @param mitreTechnique  The number of Mitre techniques.
     */
    public void addDataToChart(String category, int atomicTechnique, int mitreTechnique) {
        coveredSeries.getData().add(new XYChart.Data<>(category, atomicTechnique));
        uncoveredSeries.getData().add(new XYChart.Data<>(category, mitreTechnique - atomicTechnique));
    }

    public void initialize() {
        firstStage();

        firstChoiceBox.getSelectionModel().selectedItemProperty().addListener((observable, oldValue, newValue) ->
        {
            setChoiceBoxes(newValue);
        });

        chart.setTitle("Coverage analyse of Atomic to Mitre");
        chart.setCategoryGap(40);

        yAxis.setLabel("number of techniques");
        chart.setAnimated(false);
    }

    /**
     * Calculates the coverage ratio.
     *
     * @param totalAtomicTechnique The total number of atomic techniques.
     * @param totalMitreTechnique  The total number of Mitre techniques.
     * @return The coverage ratio as a formatted string.
     */
    private String getCoverageRatio(int totalAtomicTechnique, int totalMitreTechnique) {
        if (totalMitreTechnique == 0) {
            return "NaN";
        }
        return String.format("%.2f", (double) totalAtomicTechnique / totalMitreTechnique * 100);
    }

    /**
     * Writes the analysis result to the UI label.
     *
     * @param totalAtomicTest      The total number of atomic tests.
     * @param totalAtomicTechnique The total number of atomic techniques.
     * @param totalMitreTechnique  The total number of Mitre techniques.
     */
    private void writeAnalyseResult(int totalAtomicTest, int totalAtomicTechnique, int totalMitreTechnique) {
        String resultString = "Atomic Red Team has tests for " + totalAtomicTechnique + " of the " + totalMitreTechnique
                + " MITRE ATT&CK® Techniques for " + selectedTaxonomyString + "! (" + getCoverageRatio(totalAtomicTechnique, totalMitreTechnique)
                + "%)\nThe community has created " + totalAtomicTest + " Atomic Tests for " + selectedTaxonomyString
                + ".";

        analyseResult.setText(resultString);
    }

    /**
     * Adds tooltips to the chart nodes.
     */
    private void addTooltip() {
        String style = "-fx-font-weight: bold; -fx-font-size: 15px;";
        int totalCoveredTechnique = 0, totalUncoveredTechnique = 0;
        for (int i = 0; i < coveredSeries.getData().size(); ++i) {
            XYChart.Data<String, Number> coveredNode = coveredSeries.getData().get(i);
            XYChart.Data<String, Number> uncoveredNode = uncoveredSeries.getData().get(i);
            totalCoveredTechnique = (Integer) coveredNode.getYValue();
            totalUncoveredTechnique = (Integer) uncoveredNode.getYValue();
            String coverageRatio = "\nCOVERAGE RATIO: " + getCoverageRatio(totalCoveredTechnique, totalCoveredTechnique + totalUncoveredTechnique) + "%";
            Tooltip coveredTooltip = new Tooltip(COVERED + ": " + totalCoveredTechnique + " techniques" + coverageRatio);
            Tooltip uncoveredTooltip = new Tooltip(UNCOVERED + ": " + totalUncoveredTechnique + " techniques" + coverageRatio);

            coveredTooltip.setStyle(style);
            coveredTooltip.setShowDelay(Duration.seconds(0.05));

            uncoveredTooltip.setStyle(style);
            uncoveredTooltip.setShowDelay(Duration.seconds(0.05));

            coveredNode.getNode().addEventHandler(MouseEvent.MOUSE_MOVED,
                    event -> Tooltip.install(coveredNode.getNode(), coveredTooltip));
            uncoveredNode.getNode().addEventHandler(MouseEvent.MOUSE_MOVED,
                    event -> Tooltip.install(uncoveredNode.getNode(), uncoveredTooltip));
        }
    }

    /**
     * Generates the chart.
     */
    private void generateChart() {
        chart.getData().add(coveredSeries);
        chart.getData().add(uncoveredSeries);
        addTooltip();
    }

    /**
     * Retrieves the selected data tree based on the selected domain.
     *
     * @param selectedDomain The selected domain.
     * @return The selected data tree.
     */
    private DataTree getSelectedTree(String selectedDomain) {
        return switch (selectedDomain) {
            case "enterprise-attack" -> ENTERPRISE_TREE;
            case "mobile-attack" -> MOBILE_TREE;
            case "ics-attack" -> ICS_TREE;
            default -> ENTERPRISE_TREE;
        };
    }

    /**
     * Generates chart data for the domain-then-tactic taxonomy.
     *
     * @param selectedDomain The selected domain.
     */
    private void domainThenTactic(String selectedDomain) {
        if (selectedDomain.equals(ALL)) {
            for (String tactic : Constants.TACTICS) {
                path[1] = tactic;
                int mitreTechnique = 0, atomicTechnique = 0;
                for (String domain : Constants.DOMAINS) {
                    path[0] = domain;
                    selectedTree = getSelectedTree(domain);

                    tripleValue = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 2));
                    mitreTechnique += tripleValue.getMitreNode();
                    atomicTechnique += tripleValue.getAtomicNode().getAtomicTechnique();
                }

                addDataToChart(tactic, atomicTechnique, mitreTechnique);
            }
        } else {
            path[0] = selectedDomain;
            selectedTree = getSelectedTree(selectedDomain);

            for (String tactic : Constants.TACTICS) {
                path[1] = tactic;
                tripleValue = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 2));

                addDataToChart(tactic, tripleValue.getAtomicNode().getAtomicTechnique(), tripleValue.getMitreNode());
            }
        }

        generateChart();
    }

    /**
     * Generates chart data for the domain-then-platform taxonomy.
     *
     * @param selectedDomain The selected domain.
     */
    private void domainThenPlatform(String selectedDomain) {
        if (selectedDomain.equals(ALL)) {
            for (String platform : Constants.PLATFORMS) {
                path[2] = platform;
                int mitreTechnique = 0, atomicTechnique = 0;
                for (String domain : Constants.DOMAINS) {
                    path[0] = domain;
                    selectedTree = getSelectedTree(domain);

                    for (String tactic : Constants.TACTICS) {
                        path[1] = tactic;
                        tripleValue = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 3));

                        mitreTechnique += tripleValue.getMitreNode();
                        atomicTechnique += tripleValue.getAtomicNode().getAtomicTechnique();
                    }
                }

                addDataToChart(platform, atomicTechnique, mitreTechnique);
            }
        } else {
            path[0] = selectedDomain;
            selectedTree = getSelectedTree(selectedDomain);
            for (String platform : Constants.PLATFORMS) {
                path[2] = platform;
                int mitreTechnique = 0, atomicTechnique = 0;
                for (String tactic : Constants.TACTICS) {
                    path[1] = tactic;
                    tripleValue = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 3));
                    mitreTechnique += tripleValue.getMitreNode();
                    atomicTechnique += tripleValue.getAtomicNode().getAtomicTechnique();
                }

                addDataToChart(platform, atomicTechnique, mitreTechnique);
            }
        }

        generateChart();
    }

    /**
     * Generates chart data for the tactic-then-domain taxonomy.
     *
     * @param selectedTactic The selected tactic.
     */
    private void tacticThenDomain(String selectedTactic) {
        if (selectedTactic.equals(ALL)) {
            for (String domain : Constants.DOMAINS) {
                path[0] = domain;
                selectedTree = getSelectedTree(domain);
                tripleValue = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 1));

                addDataToChart(domain, tripleValue.getAtomicNode().getAtomicTechnique(), tripleValue.getMitreNode());
            }
        } else {
            path[1] = selectedTactic;
            for (String domain : Constants.DOMAINS) {
                path[0] = domain;
                selectedTree = getSelectedTree(domain);
                tripleValue = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 2));
                addDataToChart(domain, tripleValue.getAtomicNode().getAtomicTechnique(), tripleValue.getMitreNode());
            }
        }
        generateChart();
    }

    /**
     * Generates chart data for the tactic-then-platform taxonomy.
     *
     * @param selectedTactic The selected tactic.
     */
    private void tacticThenPlatform(String selectedTactic) {
        if (selectedTactic.equals(ALL)) {
            for (String platform : Constants.PLATFORMS) {
                path[2] = platform;
                int mitreTechnique = 0, atomicTechnique = 0;
                for (String domain : Constants.DOMAINS) {
                    path[0] = domain;
                    selectedTree = getSelectedTree(domain);

                    for (String tactic : Constants.TACTICS) {
                        path[1] = tactic;
                        tripleValue = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 3));
                        mitreTechnique += tripleValue.getMitreNode();
                        atomicTechnique += tripleValue.getAtomicNode().getAtomicTechnique();
                    }
                }

                addDataToChart(platform, atomicTechnique, mitreTechnique);
            }
        } else {
            Object value;
            path[1] = selectedTactic;
            for (String platform : Constants.PLATFORMS) {
                path[2] = platform;
                int mitreTechnique = 0, atomicTechnique = 0;
                for (String domain : Constants.DOMAINS) {
                    path[0] = domain;
                    selectedTree = getSelectedTree(domain);
                    path[3] = MITRE_TOTAL;
                    value = selectedTree.getValue(path);
                    mitreTechnique += (Integer) value;
                    path[3] = ATOMIC_TOTAL;
                    value = selectedTree.getValue(path);
                    atomicTechnique += ((Pair) value).getAtomicTechnique();
                }

                addDataToChart(platform, atomicTechnique, mitreTechnique);
            }
        }

        generateChart();
    }

    /**
     * Generates chart data for the platform-then-tactic taxonomy.
     *
     * @param selectedPlatform The selected platform.
     */
    private void platformThenTactic(String selectedPlatform) {
        if (selectedPlatform.equals(ALL)) {
            for (String tactic : Constants.TACTICS) {
                path[1] = tactic;
                int mitreTechnique = 0, atomicTechnique = 0;
                for (String domain : Constants.DOMAINS) {
                    path[0] = domain;
                    selectedTree = getSelectedTree(domain);
                    tripleValue = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 2));
                    mitreTechnique += tripleValue.getMitreNode();
                    atomicTechnique += tripleValue.getAtomicNode().getAtomicTechnique();
                }
                addDataToChart(tactic, atomicTechnique, mitreTechnique);
            }
        } else {
            Object value;
            path[2] = selectedPlatform;
            for (String tactic : Constants.TACTICS) {
                path[1] = tactic;
                int mitreTechnique = 0, atomicTechnique = 0;
                for (String domain : Constants.DOMAINS) {
                    path[0] = domain;
                    selectedTree = getSelectedTree(domain);
                    path[3] = MITRE_TOTAL;
                    value = selectedTree.getValue(path);
                    mitreTechnique += (Integer) value;
                    path[3] = ATOMIC_TOTAL;
                    value = selectedTree.getValue(path);
                    atomicTechnique += ((Pair) value).getAtomicTechnique();
                }

                addDataToChart(tactic, atomicTechnique, mitreTechnique);
            }
        }

        generateChart();
    }

    /**
     * Generates chart data for the platform-then-domain taxonomy.
     *
     * @param selectedPlatform The selected platform.
     */
    private void platformThenDomain(String selectedPlatform) {
        if (selectedPlatform.equals(ALL)) {
            for (String domain : Constants.DOMAINS) {
                path[0] = domain;
                selectedTree = getSelectedTree(domain);
                tripleValue = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 1));
                addDataToChart(domain, tripleValue.getAtomicNode().getAtomicTechnique(), tripleValue.getMitreNode());
            }
        } else {
            path[2] = selectedPlatform;
            for (String domain : Constants.DOMAINS) {
                path[0] = domain;
                selectedTree = getSelectedTree(domain);
                int mitreTechnique = 0, atomicTechnique = 0;
                for (String tactic : Constants.TACTICS) {
                    path[1] = tactic;
                    tripleValue = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 3));

                    mitreTechnique += tripleValue.getMitreNode();
                    atomicTechnique += tripleValue.getAtomicNode().getAtomicTechnique();
                }
                addDataToChart(domain, atomicTechnique, mitreTechnique);
            }
        }

        generateChart();
    }

    /**
     * Handles the button click event for the "Analyse" button.
     */
    @FXML
    void analyseButtonPressed(ActionEvent event) {
        // Get the selected choices
        String firstChoice = firstChoiceBox.getSelectionModel().getSelectedItem();
        String secondChoice = secondChoiceBox.getSelectionModel().getSelectedItem();
        String thirdChoice = thirdChoiceBox.getSelectionModel().getSelectedItem();

        xAxis.setLabel(thirdChoice);

        // Clear existing data
        chart.getData().clear();
        xAxis.getCategories().clear();
        coveredSeries.getData().clear();
        uncoveredSeries.getData().clear();

        if (thirdChoice.equals(TAXONOMIES.get(2))) {
            xAxis.setTickLabelRotation(-90);
            xAxis.setCategories(FXCollections.observableArrayList(Constants.PLATFORMS));
        } else {
            xAxis.setTickLabelRotation(-45);
            if (thirdChoice.equals(TAXONOMIES.get(0))) {
                xAxis.setCategories(FXCollections.observableArrayList(Constants.DOMAINS));
            } else {
                xAxis.setCategories(FXCollections.observableArrayList(Constants.TACTICS));
            }
        }

        // Generate new data based on the selected choices
        Triple selectedNode;
        int totalMitreTechnique = 0, totalAtomicTechnique = 0, totalAtomicTest = 0;

        if (secondChoice.equals(ALL)) {
            for (String domain : Constants.DOMAINS) {
                path[0] = domain;
                selectedTree = getSelectedTree(domain);
                selectedNode = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 1));
                totalMitreTechnique += selectedNode.getMitreNode();
                totalAtomicTechnique += selectedNode.getAtomicNode().getAtomicTechnique();
                totalAtomicTest += selectedNode.getAtomicNode().getAtomicTest();
            }
        }

        if (firstChoice.equals(TAXONOMIES.get(0))) {
            if (secondChoice.equals(ALL)) {
                selectedTaxonomyString = "all of the domains";
            } else {
                selectedTaxonomyString = secondChoice.toUpperCase();
                selectedTree = getSelectedTree(secondChoice);

                selectedNode = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 1));
                totalMitreTechnique = selectedNode.getMitreNode();
                totalAtomicTechnique = selectedNode.getAtomicNode().getAtomicTechnique();
                totalAtomicTest = selectedNode.getAtomicNode().getAtomicTest();
            }
            if (thirdChoice.equals(TAXONOMIES.get(1))) {
                domainThenTactic(secondChoice);
            } else {
                domainThenPlatform(secondChoice);
            }
        }

        if (firstChoice.equals(TAXONOMIES.get(1))) {
            if (secondChoice.equals(ALL)) {
                selectedTaxonomyString = "all of the tactics";
            } else {
                selectedTaxonomyString = secondChoice.toUpperCase();
                path[1] = secondChoice;
                for (String domain : Constants.DOMAINS) {
                    path[0] = domain;
                    selectedTree = getSelectedTree(domain);
                    selectedNode = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 2));
                    totalMitreTechnique += selectedNode.getMitreNode();
                    totalAtomicTechnique += selectedNode.getAtomicNode().getAtomicTechnique();
                    totalAtomicTest += selectedNode.getAtomicNode().getAtomicTest();
                }
            }
            if (thirdChoice.equals(TAXONOMIES.get(0))) {
                tacticThenDomain(secondChoice);
            } else {
                tacticThenPlatform(secondChoice);
            }
        }

        if (firstChoice.equals(TAXONOMIES.get(2))) {
            if (secondChoice.equals(ALL)) {
                selectedTaxonomyString = "all of the platforms";
            } else {
                selectedTaxonomyString = secondChoice.toUpperCase();
                path[2] = secondChoice;
                for (String domain : Constants.DOMAINS) {
                    path[0] = domain;
                    selectedTree = getSelectedTree(domain);
                    for (String tactic : Constants.TACTICS) {
                        path[1] = tactic;
                        selectedNode = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 3));
                        totalMitreTechnique += selectedNode.getMitreNode();
                        totalAtomicTechnique += selectedNode.getAtomicNode().getAtomicTechnique();
                        totalAtomicTest += selectedNode.getAtomicNode().getAtomicTest();
                    }
                }
            }
            if (thirdChoice.equals(TAXONOMIES.get(0))) {
                platformThenDomain(secondChoice);
            } else {
                platformThenTactic(secondChoice);
            }
        }

        writeAnalyseResult(totalAtomicTest, totalAtomicTechnique, totalMitreTechnique);
    }

    /**
     * Handles the button click event for the "Save" button.
     */
    @FXML
    void saveButtonPressed(ActionEvent event) {
        String firstChoice = firstChoiceBox.getSelectionModel().getSelectedItem();
        String secondChoice = secondChoiceBox.getSelectionModel().getSelectedItem();
        String thirdChoice = thirdChoiceBox.getSelectionModel().getSelectedItem();

        if (secondChoice.equals(ALL)) {
            secondChoice = "ALL";
        }

        String directoryPath = "./data/coverage-analysis";

        File directory = new File(directoryPath);

        // Create the directory if it doesn't exist
        if (!directory.exists()) {
            directory.mkdirs();
        }

        String filePath = directoryPath + "/" + firstChoice + "-" + secondChoice + "-" + thirdChoice + ".png";

        // Capture the screen image
        WritableImage image = screenBorder.snapshot(null, null);

        File file = new File(filePath);

        try {
            ImageIO.write(SwingFXUtils.fromFXImage(image, null), "png", file);
            System.out.println("Chart image saved successfully.");
            openFile(file.getAbsolutePath());
        } catch (IOException e) {
            System.out.println("Error saving chart image: " + e.getMessage());
        }
    }

    /**
     * Opens the specified file.
     *
     * @param filePath The path of the file to open.
     */
    private void openFile(String filePath) {
        try {
            File file = new File(filePath);
            if (file.exists()) {
                Desktop.getDesktop().open(file);
            } else {
                System.err.println("File not found: " + filePath);
            }
        } catch (IOException e) {
            System.err.println(e.getMessage());
        }
    }
}