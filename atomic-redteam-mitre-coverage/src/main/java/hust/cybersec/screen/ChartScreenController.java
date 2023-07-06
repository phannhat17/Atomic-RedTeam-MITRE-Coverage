package hust.cybersec.screen;

import hust.cybersec.data.process.*;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
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

import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;

import javafx.embed.swing.SwingFXUtils;
import javafx.scene.text.Font;

import javax.imageio.ImageIO;
import javax.swing.text.Style;

public class ChartScreenController
{
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

	private final XYChart.Series<String, Number> coveredSeries = new XYChart.Series<>();

	private final XYChart.Series<String, Number> uncoveredSeries = new XYChart.Series<>();

	private final ObservableList<String> PLATFORMS = FXCollections.observableArrayList(Constants.PLATFORMS);
	private final ObservableList<String> TACTICS = FXCollections.observableArrayList(Constants.TACTICS);
	private final ObservableList<String> DOMAINS = FXCollections.observableArrayList(Constants.DOMAINS);
	private final ObservableList<String> TAXONOMIES = FXCollections.observableArrayList("domain", "tactic", "platform");
	private final String ALL = "---------- ALL ------------";

	private final String COVERED = "Covered";
	private final String UNCOVERED = "Uncovered";

	private final JsonToTreeProcessor processor = new JsonToTreeProcessor();

	{
		DOMAINS.add(ALL);
		TACTICS.add(ALL);
		PLATFORMS.add(ALL);
		processor.buildDataTree();
		coveredSeries.setName(COVERED);
		uncoveredSeries.setName(UNCOVERED);
	}

	private final DataTree ENTERPRISE_TREE = processor.getEnterpriseTree();
	private final DataTree MOBILE_TREE = processor.getMobileTree();
	private final DataTree ICS_TREE = processor.getIcsTree();
	private final String[] path = new String[4];
	private final String MITRE_TOTAL = "Mitre.Total";
	private final String ATOMIC_TOTAL = "Atomic.Total";

	private DataTree selectedTree;

	private Triple tripleValue;

	private String selectedTaxonomyString = "";

	public void firstStage()
	{
		// Set for initial stage
		ObservableList<String> firstChoices = FXCollections.observableArrayList(TAXONOMIES);
		firstChoiceBox.setItems(firstChoices.sorted());
		firstChoiceBox.getSelectionModel().select(TAXONOMIES.get(0));

		String selectedFirstChoice = firstChoiceBox.getSelectionModel().getSelectedItem();
		setChoiceBoxes(selectedFirstChoice);
		analyseButtonPressed(new ActionEvent());
	}

	public void setChoiceBoxes(String selectedFirstChoice)
	{
		if (selectedFirstChoice.equals(TAXONOMIES.get(0)))
		{
			secondChoiceBox.setItems(DOMAINS.sorted());
			thirdChoiceBox.setItems(FXCollections.observableArrayList(TAXONOMIES.get(1), TAXONOMIES.get(2)));
		}
		else if (selectedFirstChoice.equals(TAXONOMIES.get(1)))
		{
			secondChoiceBox.setItems(TACTICS.sorted());
			thirdChoiceBox.setItems(FXCollections.observableArrayList(TAXONOMIES.get(0), TAXONOMIES.get(2)));
		}
		else if (selectedFirstChoice.equals(TAXONOMIES.get(2)))
		{
			secondChoiceBox.setItems(PLATFORMS.sorted());
			thirdChoiceBox.setItems(FXCollections.observableArrayList(TAXONOMIES.get(1), TAXONOMIES.get(0)));
		}
		secondChoiceBox.getSelectionModel().select(ALL);
		thirdChoiceBox.getSelectionModel().selectFirst();
	}

	public void initialize()
	{
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

	private double calculateCoverageRate(int numMitreTechnique, int numAtomicTechnique)
	{
		return (double) numAtomicTechnique / numMitreTechnique * 100;
	}

	private void writeAnalyseResult(int numAtomicTest, int numAtomicTechnique, int numMitreTechnique,
			double coverageRate)
	{
		String resultString = "Atomic Red Team has tests for " + numAtomicTechnique + " of the " + numMitreTechnique
				+ " MITRE ATT&CK® Techniques for " + selectedTaxonomyString + "! (" + coverageRate
				+ "%)\nThe community has created " + numAtomicTest + " Atomic Tests for " + selectedTaxonomyString
				+ ".";

		analyseResult.setText(resultString);
	}

	private void addTooltip()
	{
		String style = "-fx-font-weight: bold; -fx-font-size: 15px;";
		for (XYChart.Data<String, Number> data : coveredSeries.getData())
		{
			Tooltip tooltip = new Tooltip(COVERED + ": " + data.getYValue());
			tooltip.setStyle(style);
			data.getNode().addEventHandler(MouseEvent.MOUSE_MOVED,
					(EventHandler<MouseEvent>) event -> Tooltip.install(data.getNode(), tooltip));
		}
		for (XYChart.Data<String, Number> data : uncoveredSeries.getData())
		{
			Tooltip tooltip = new Tooltip(UNCOVERED + ": " + data.getYValue());
			tooltip.setStyle(style);
			data.getNode().addEventHandler(MouseEvent.MOUSE_MOVED,
					(EventHandler<MouseEvent>) event -> Tooltip.install(data.getNode(), tooltip));
		}
	}

	private void generateChart()
	{
		chart.getData().add(coveredSeries);
		chart.getData().add(uncoveredSeries);
		addTooltip();
	}

	private DataTree getSelectedTree(String selectedDomain)
	{
		return switch (selectedDomain)
		{
			case "enterprise-attack" -> ENTERPRISE_TREE;
			case "mobile-attack" -> MOBILE_TREE;
			case "ics-attack" -> ICS_TREE;
			default -> null;
		};

	}

	private void domainThenTactic(String selectedDomain)
	{
		if (selectedDomain.equals(ALL))
		{
			for (String tactic : Constants.TACTICS)
			{
				path[1] = tactic;
				int mitreTotal = 0, atomicTechnique = 0;
				for (String domain : Constants.DOMAINS)
				{
					path[0] = domain;
					selectedTree = getSelectedTree(domain);

					tripleValue = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 2));
					mitreTotal += tripleValue.getMitreNode();
					atomicTechnique += tripleValue.getAtomicNode().getAtomicTechnique();
				}

				coveredSeries.getData().add(new XYChart.Data<>(tactic, atomicTechnique));
				uncoveredSeries.getData().add(new XYChart.Data<>(tactic, mitreTotal - atomicTechnique));
			}
		}
		else
		{
			path[0] = selectedDomain;
			selectedTree = getSelectedTree(selectedDomain);

			for (String tactic : Constants.TACTICS)
			{
				path[1] = tactic;
				tripleValue = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 2));
				coveredSeries.getData()
						.add(new XYChart.Data<>(tactic, tripleValue.getAtomicNode().getAtomicTechnique()));
				uncoveredSeries.getData().add(new XYChart.Data<>(tactic,
						tripleValue.getMitreNode() - tripleValue.getAtomicNode().getAtomicTechnique()));
			}
		}

		generateChart();
	}

	private void domainThenPlatform(String selectedDomain)
	{
		if (selectedDomain.equals(ALL))
		{
			for (String platform : Constants.PLATFORMS)
			{
				path[2] = platform;
				int mitreTotal = 0, atomicTechnique = 0;
				for (String domain : Constants.DOMAINS)
				{
					path[0] = domain;
					selectedTree = getSelectedTree(domain);

					for (String tactic : Constants.TACTICS)
					{
						path[1] = tactic;
						tripleValue = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 3));

						mitreTotal += tripleValue.getMitreNode();
						atomicTechnique += tripleValue.getAtomicNode().getAtomicTechnique();
					}
				}

				coveredSeries.getData().add(new XYChart.Data<>(platform, atomicTechnique));
				uncoveredSeries.getData().add(new XYChart.Data<>(platform, mitreTotal - atomicTechnique));
			}
		}
		else
		{
			path[0] = selectedDomain;
			selectedTree = getSelectedTree(selectedDomain);
			for (String platform : Constants.PLATFORMS)
			{
				path[2] = platform;
				int mitreTotal = 0, atomicTechnique = 0;
				for (String tactic : Constants.TACTICS)
				{
					path[1] = tactic;
					tripleValue = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 3));
					mitreTotal += tripleValue.getMitreNode();
					atomicTechnique += tripleValue.getAtomicNode().getAtomicTechnique();
				}

				coveredSeries.getData().add(new XYChart.Data<>(platform, atomicTechnique));
				uncoveredSeries.getData().add(new XYChart.Data<>(platform, mitreTotal - atomicTechnique));
			}
		}

		generateChart();
	}

	private void tacticThenDomain(String selectedTactic)
	{
		if (selectedTactic.equals(ALL))
		{
			for (String domain : Constants.DOMAINS)
			{
				path[0] = domain;
				selectedTree = getSelectedTree(domain);
				tripleValue = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 1));

				coveredSeries.getData()
						.add(new XYChart.Data<>(path[0], tripleValue.getAtomicNode().getAtomicTechnique()));
				uncoveredSeries.getData().add(new XYChart.Data<>(path[0],
						tripleValue.getMitreNode() - tripleValue.getAtomicNode().getAtomicTechnique()));
			}
		}
		else
		{
			path[1] = selectedTactic;
			for (String domain : Constants.DOMAINS)
			{
				path[0] = domain;
				selectedTree = getSelectedTree(domain);
				tripleValue = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 2));
				coveredSeries.getData()
						.add(new XYChart.Data<>(path[0], tripleValue.getAtomicNode().getAtomicTechnique()));
				uncoveredSeries.getData().add(new XYChart.Data<>(path[0],
						tripleValue.getMitreNode() - tripleValue.getAtomicNode().getAtomicTechnique()));
			}
		}
		generateChart();
	}

	private void tacticThenPlatform(String selectedTactic)
	{
		if (selectedTactic.equals(ALL))
		{
			for (String platform : Constants.PLATFORMS)
			{
				path[2] = platform;
				int mitreTotal = 0, atomicTechnique = 0;
				for (String domain : Constants.DOMAINS)
				{
					path[0] = domain;
					selectedTree = getSelectedTree(domain);

					for (String tactic : Constants.TACTICS)
					{
						path[1] = tactic;
						tripleValue = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 3));
						mitreTotal += tripleValue.getMitreNode();
						atomicTechnique += tripleValue.getAtomicNode().getAtomicTechnique();
					}
				}

				coveredSeries.getData().add(new XYChart.Data<>(platform, atomicTechnique));
				uncoveredSeries.getData().add(new XYChart.Data<>(platform, mitreTotal - atomicTechnique));
			}
		}
		else
		{
			Object value;
			path[1] = selectedTactic;
			for (String platform : Constants.PLATFORMS)
			{
				path[2] = platform;
				int mitreTotal = 0, atomicTechnique = 0;
				for (String domain : Constants.DOMAINS)
				{
					path[0] = domain;
					selectedTree = getSelectedTree(domain);
					path[3] = MITRE_TOTAL;
					value = selectedTree.getValue(path);
					mitreTotal += (Integer) value;
					path[3] = ATOMIC_TOTAL;
					value = selectedTree.getValue(path);
					atomicTechnique += ((Pair) value).getAtomicTechnique();
				}
				coveredSeries.getData().add(new XYChart.Data<>(platform, atomicTechnique));
				uncoveredSeries.getData().add(new XYChart.Data<>(platform, mitreTotal - atomicTechnique));
			}
		}

		generateChart();
	}

	private void platformThenTactic(String selectedPlatform)
	{
		if (selectedPlatform.equals(ALL))
		{
			for (String tactic : Constants.TACTICS)
			{
				path[1] = tactic;
				int mitreTotal = 0, atomicTechnique = 0;
				for (String domain : Constants.DOMAINS)
				{
					path[0] = domain;
					selectedTree = getSelectedTree(domain);
					tripleValue = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 2));
					mitreTotal += tripleValue.getMitreNode();
					atomicTechnique += tripleValue.getAtomicNode().getAtomicTechnique();
				}
				coveredSeries.getData().add(new XYChart.Data<>(tactic, atomicTechnique));
				uncoveredSeries.getData().add(new XYChart.Data<>(tactic, mitreTotal - atomicTechnique));
			}
		}
		else
		{
			Object value;
			path[2] = selectedPlatform;
			for (String tactic : Constants.TACTICS)
			{
				path[1] = tactic;
				int mitreTotal = 0, atomicTechnique = 0;
				for (String domain : Constants.DOMAINS)
				{
					path[0] = domain;
					selectedTree = getSelectedTree(domain);
					path[3] = MITRE_TOTAL;
					value = selectedTree.getValue(path);
					mitreTotal += (Integer) value;
					path[3] = ATOMIC_TOTAL;
					value = selectedTree.getValue(path);
					atomicTechnique += ((Pair) value).getAtomicTechnique();
				}

				coveredSeries.getData().add(new XYChart.Data<>(tactic, atomicTechnique));
				uncoveredSeries.getData().add(new XYChart.Data<>(tactic, mitreTotal - atomicTechnique));
			}
		}

		generateChart();
	}

	private void platformThenDomain(String selectedPlatform)
	{
		if (selectedPlatform.equals(ALL))
		{
			for (String domain : Constants.DOMAINS)
			{
				path[0] = domain;
				selectedTree = getSelectedTree(domain);
				tripleValue = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 1));
				coveredSeries.getData()
						.add(new XYChart.Data<>(path[0], tripleValue.getAtomicNode().getAtomicTechnique()));
				uncoveredSeries.getData().add(new XYChart.Data<>(path[0],
						tripleValue.getMitreNode() - tripleValue.getAtomicNode().getAtomicTechnique()));
			}
		}
		else
		{
			path[2] = selectedPlatform;
			for (String domain : Constants.DOMAINS)
			{
				path[0] = domain;
				selectedTree = getSelectedTree(domain);
				int mitreTotal = 0, atomicTechnique = 0;
				for (String tactic : Constants.TACTICS)
				{
					path[1] = tactic;
					tripleValue = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 3));

					mitreTotal += tripleValue.getMitreNode();
					atomicTechnique += tripleValue.getAtomicNode().getAtomicTechnique();
				}
				coveredSeries.getData().add(new XYChart.Data<>(path[0], atomicTechnique));
				uncoveredSeries.getData().add(new XYChart.Data<>(path[0], mitreTotal - atomicTechnique));
			}
		}

		generateChart();
	}

	@FXML
	void analyseButtonPressed(ActionEvent event)
	{
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

		if (thirdChoice.equals(TAXONOMIES.get(2)))
		{
			xAxis.setTickLabelRotation(-90);
			xAxis.setCategories(FXCollections.observableArrayList(Constants.PLATFORMS));
		}
		else
		{
			xAxis.setTickLabelRotation(-45);
			if (thirdChoice.equals(TAXONOMIES.get(0)))
			{
				xAxis.setCategories(FXCollections.observableArrayList(Constants.DOMAINS));
			}
			else
			{
				xAxis.setCategories(FXCollections.observableArrayList(Constants.TACTICS));
			}
		}

		// Generate new data based on the selected choices
		Triple selectedNode;
		int numMitreTechnique = 0, numAtomicTechnique = 0, numAtomicTest = 0;

		if (secondChoice.equals(ALL))
		{
			for (String domain : Constants.DOMAINS)
			{
				path[0] = domain;
				selectedTree = getSelectedTree(domain);
				selectedNode = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 1));
				numMitreTechnique += selectedNode.getMitreNode();
				numAtomicTechnique += selectedNode.getAtomicNode().getAtomicTechnique();
				numAtomicTest += selectedNode.getAtomicNode().getAtomicTest();
			}
		}

		if (firstChoice.equals(TAXONOMIES.get(0)))
		{
			if (secondChoice.equals(ALL))
			{
				selectedTaxonomyString = "all of the domains";
			}
			else
			{
				selectedTaxonomyString = secondChoice.toUpperCase();
				selectedTree = getSelectedTree(secondChoice);

				selectedNode = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 1));
				numMitreTechnique = selectedNode.getMitreNode();
				numAtomicTechnique = selectedNode.getAtomicNode().getAtomicTechnique();
				numAtomicTest = selectedNode.getAtomicNode().getAtomicTest();
			}
			if (thirdChoice.equals(TAXONOMIES.get(1)))
			{
				domainThenTactic(secondChoice);
			}
			else
			{
				domainThenPlatform(secondChoice);
			}
		}

		if (firstChoice.equals(TAXONOMIES.get(1)))
		{
			if (secondChoice.equals(ALL))
			{
				selectedTaxonomyString = "all of the tactics";
			}
			else
			{
				selectedTaxonomyString = secondChoice.toUpperCase();
				path[1] = secondChoice;
				for (String domain : Constants.DOMAINS)
				{
					path[0] = domain;
					selectedTree = getSelectedTree(domain);
					selectedNode = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 2));
					numMitreTechnique += selectedNode.getMitreNode();
					numAtomicTechnique += selectedNode.getAtomicNode().getAtomicTechnique();
					numAtomicTest += selectedNode.getAtomicNode().getAtomicTest();
				}
			}
			if (thirdChoice.equals(TAXONOMIES.get(0)))
			{
				tacticThenDomain(secondChoice);
			}
			else
			{
				tacticThenPlatform(secondChoice);
			}
		}

		if (firstChoice.equals(TAXONOMIES.get(2)))
		{
			if (secondChoice.equals(ALL))
			{
				selectedTaxonomyString = "all of the platforms";
			}
			else
			{
				selectedTaxonomyString = secondChoice.toUpperCase();
				path[2] = secondChoice;
				for (String domain : Constants.DOMAINS)
				{
					path[0] = domain;
					selectedTree = getSelectedTree(domain);
					for (String tactic : Constants.TACTICS)
					{
						path[1] = tactic;
						selectedNode = (Triple) selectedTree.getValue(Arrays.copyOfRange(path, 0, 3));
						numMitreTechnique += selectedNode.getMitreNode();
						numAtomicTechnique += selectedNode.getAtomicNode().getAtomicTechnique();
						numAtomicTest += selectedNode.getAtomicNode().getAtomicTest();
					}
				}
			}
			if (thirdChoice.equals(TAXONOMIES.get(0)))
			{
				platformThenDomain(secondChoice);
			}
			else
			{
				platformThenTactic(secondChoice);
			}
		}

		writeAnalyseResult(numAtomicTest, numAtomicTechnique, numMitreTechnique,
				calculateCoverageRate(numMitreTechnique, numAtomicTechnique));
	}

	@FXML
	void saveButtonPressed(ActionEvent event)
	{
		String firstChoice = firstChoiceBox.getSelectionModel().getSelectedItem();
		String secondChoice = secondChoiceBox.getSelectionModel().getSelectedItem();
		String thirdChoice = thirdChoiceBox.getSelectionModel().getSelectedItem();

		if (secondChoice.equals(ALL))
		{
			secondChoice = "ALL";
		}

		String directoryPath = "./data/coverage-analysis";

		File directory = new File(directoryPath);

		// Create the directory if it doesn't exist
		if (!directory.exists())
		{
			directory.mkdirs();
		}

		String filePath = directoryPath + "/" + firstChoice + "-" + secondChoice + "-" + thirdChoice + ".png";

		// Capture the screen image
		WritableImage image = screenBorder.snapshot(null, null);

		File file = new File(filePath);

		try
		{
			ImageIO.write(SwingFXUtils.fromFXImage(image, null), "png", file);
			System.out.println("Chart image saved successfully.");
			openFile(file.getAbsolutePath());
		}
		catch (IOException e)
		{
			System.out.println("Error saving chart image: " + e.getMessage());
		}
	}

	private void openFile(String filePath)
	{
		try
		{
			File file = new File(filePath);
			if (file.exists())
			{
				Desktop.getDesktop().open(file);
			}
			else
			{
				System.err.println("File not found: " + filePath);
			}
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
	}
}