package hust.cybersec.screen;

import hust.cybersec.data.process.*;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.chart.CategoryAxis;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.StackedBarChart;
import javafx.scene.chart.XYChart;
import javafx.scene.control.Button;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.Label;
import javafx.scene.image.WritableImage;
import javafx.scene.layout.BorderPane;
import javafx.stage.FileChooser;

import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;

import javafx.embed.swing.SwingFXUtils;
import javafx.scene.image.WritableImage;

import javax.imageio.ImageIO;

import javafx.stage.FileChooser;

import java.io.File;
import java.io.IOException;

public class ChartScreenController
{

	@FXML
	private Button analyseButton;

	@FXML
	private Label analyseResult;

	@FXML
	private StackedBarChart<String, Number> chart;

	@FXML
	private ChoiceBox<String> firstChoiceBox;

	@FXML
	private Button saveButton;

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

	private final ObservableList<String> PLATFORMS = FXCollections.observableArrayList(Constants.PLATFORMS);
	private final ObservableList<String> TACTICS = FXCollections.observableArrayList(Constants.TACTICS);
	private final ObservableList<String> DOMAINS = FXCollections.observableArrayList(Constants.DOMAINS);
	private final ObservableList<String> TAXONOMIES = FXCollections.observableArrayList("domain", "tactic", "platform");
	private final String ALL = "---------- ALL ------------";

	{
		DOMAINS.add(ALL);
		TACTICS.add(ALL);
		PLATFORMS.add(ALL);
	}

	private final JsonToTreeProcessor processor = new JsonToTreeProcessor();

	{
		processor.buildDataTree();
	}

	private final DataTree enterpriseTree = processor.getEnterpriseTree();
	private final DataTree mobileTree = processor.getMobileTree();
	private final DataTree icsTree = processor.getIcsTree();
	private final String[] path = new String[4];

	private final String COVERED = "Covered";
	private final String UNCOVERED = "Uncovered";

	private final String MITRE_TOTAL = "Mitre.Total";
	private final String ATOMIC_TOTAL = "Atomic.Total";

	private String selectedTaxonomyString = "";

	public void firstStage()
	{
		// Set for initial stage
		ObservableList<String> firstChoices = FXCollections.observableArrayList(TAXONOMIES);
		firstChoiceBox.setItems(firstChoices.sorted());
		firstChoiceBox.getSelectionModel().select(TAXONOMIES.get(0));

		String selectedFirstChoice = firstChoiceBox.getSelectionModel().getSelectedItem();
		if (selectedFirstChoice.equals(TAXONOMIES.get(0)))
		{
			secondChoiceBox.setItems(DOMAINS.sorted());
			thirdChoiceBox.setItems(FXCollections.observableArrayList(TAXONOMIES.get(1), TAXONOMIES.get(2)));
		}
		else if (selectedFirstChoice.equals(TAXONOMIES.get(1)))
		{
			secondChoiceBox.setItems(TACTICS.sorted());
			thirdChoiceBox.setItems(FXCollections.observableArrayList(TAXONOMIES.get(1), TAXONOMIES.get(0)));
		}
		else if (selectedFirstChoice.equals(TAXONOMIES.get(2)))
		{
			secondChoiceBox.setItems(PLATFORMS.sorted());
			thirdChoiceBox.setItems(FXCollections.observableArrayList(TAXONOMIES.get(1), TAXONOMIES.get(0)));
		}
		secondChoiceBox.getSelectionModel().select(ALL);
		thirdChoiceBox.getSelectionModel().selectFirst();
		analyseButtonPressed(new ActionEvent());
	}

	public void initialize()
	{
		firstStage();

		firstChoiceBox.getSelectionModel().selectedItemProperty().addListener((observable, oldValue, newValue) ->
		{
			if (newValue.equals(TAXONOMIES.get(0)))
			{
				secondChoiceBox.setItems(DOMAINS.sorted());
				thirdChoiceBox.setItems(FXCollections.observableArrayList(TAXONOMIES.get(1), TAXONOMIES.get(2)));
			}
			else if (newValue.equals(TAXONOMIES.get(1)))
			{
				secondChoiceBox.setItems(TACTICS.sorted());
				thirdChoiceBox.setItems(FXCollections.observableArrayList(TAXONOMIES.get(0), TAXONOMIES.get(2)));
			}
			else if (newValue.equals(TAXONOMIES.get(2)))
			{
				secondChoiceBox.setItems(PLATFORMS.sorted());
				thirdChoiceBox.setItems(FXCollections.observableArrayList(TAXONOMIES.get(1), TAXONOMIES.get(0)));
			}
			secondChoiceBox.getSelectionModel().select(ALL);
			thirdChoiceBox.getSelectionModel().selectFirst();
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

	private void domainThenTactic(String selectedDomain)
	{
		XYChart.Series<String, Number> coveredSeries = new XYChart.Series<>();
		coveredSeries.setName(COVERED);

		XYChart.Series<String, Number> uncoveredSeries = new XYChart.Series<>();
		uncoveredSeries.setName(UNCOVERED);

		DataTree selectedTree;
		Triple tripleValue;

		if (selectedDomain.equals(ALL))
		{
			for (String tactic : Constants.TACTICS)
			{
				path[1] = tactic;
				int mitreTotal = 0, atomicTechnique = 0;
				for (int i = 0; i < 3; ++i)
				{
					path[0] = Constants.DOMAINS[i];
					if (i == 0)
					{
						selectedTree = enterpriseTree;
					}
					else if (i == 1)
					{
						selectedTree = mobileTree;
					}
					else
					{
						selectedTree = icsTree;
					}

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
			if (selectedDomain.equals(Constants.DOMAINS[0]))
			{
				selectedTree = enterpriseTree;
			}
			else if (selectedDomain.equals(Constants.DOMAINS[1]))
			{
				selectedTree = mobileTree;
			}
			else
			{
				selectedTree = icsTree;
			}

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

		chart.getData().add(coveredSeries);
		chart.getData().add(uncoveredSeries);
	}

	private void domainThenPlatform(String selectedDomain)
	{
		XYChart.Series<String, Number> coveredSeries = new XYChart.Series<>();
		coveredSeries.setName(COVERED);

		XYChart.Series<String, Number> uncoveredSeries = new XYChart.Series<>();
		uncoveredSeries.setName(UNCOVERED);

		DataTree selectedTree;
		Triple tripleValue;

		if (selectedDomain.equals(ALL))
		{
			for (String platform : Constants.PLATFORMS)
			{
				path[2] = platform;
				int mitreTotal = 0, atomicTechnique = 0;
				for (int i = 0; i < 3; ++i)
				{
					path[0] = Constants.DOMAINS[i];
					if (i == 0)
					{
						selectedTree = enterpriseTree;
					}
					else if (i == 1)
					{
						selectedTree = mobileTree;
					}
					else
					{
						selectedTree = icsTree;
					}

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
			if (selectedDomain.equals(Constants.DOMAINS[0]))
			{
				selectedTree = enterpriseTree;
			}
			else if (selectedDomain.equals(Constants.DOMAINS[1]))
			{
				selectedTree = mobileTree;
			}
			else
			{
				selectedTree = icsTree;
			}
			path[0] = selectedDomain;
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

		chart.getData().add(coveredSeries);
		chart.getData().add(uncoveredSeries);
	}

	private void tacticThenDomain(String selectedTactic)
	{
		XYChart.Series<String, Number> coveredSeries = new XYChart.Series<>();
		coveredSeries.setName(COVERED);

		XYChart.Series<String, Number> uncoveredSeries = new XYChart.Series<>();
		uncoveredSeries.setName(UNCOVERED);

		if (selectedTactic.equals(ALL))
		{
			for (int i = 0; i < 3; ++i)
			{
				path[0] = Constants.DOMAINS[i];
				Triple tripleValue;
				if (i == 0)
				{
					tripleValue = (Triple) enterpriseTree.getValue(Arrays.copyOfRange(path, 0, 1));
				}
				else if (i == 1)
				{
					tripleValue = (Triple) mobileTree.getValue(Arrays.copyOfRange(path, 0, 1));
				}
				else
				{
					tripleValue = (Triple) icsTree.getValue(Arrays.copyOfRange(path, 0, 1));
				}
				coveredSeries.getData()
						.add(new XYChart.Data<>(path[0], tripleValue.getAtomicNode().getAtomicTechnique()));
				uncoveredSeries.getData().add(new XYChart.Data<>(path[0],
						tripleValue.getMitreNode() - tripleValue.getAtomicNode().getAtomicTechnique()));
			}
		}
		else
		{
			path[1] = selectedTactic;
			for (int i = 0; i < 3; ++i)
			{
				path[0] = Constants.DOMAINS[i];
				Triple tripleValue;
				if (i == 0)
				{
					tripleValue = (Triple) enterpriseTree.getValue(Arrays.copyOfRange(path, 0, 2));
				}
				else if (i == 1)
				{
					tripleValue = (Triple) mobileTree.getValue(Arrays.copyOfRange(path, 0, 2));
				}
				else
				{
					tripleValue = (Triple) icsTree.getValue(Arrays.copyOfRange(path, 0, 2));
				}
				coveredSeries.getData()
						.add(new XYChart.Data<>(path[0], tripleValue.getAtomicNode().getAtomicTechnique()));
				uncoveredSeries.getData().add(new XYChart.Data<>(path[0],
						tripleValue.getMitreNode() - tripleValue.getAtomicNode().getAtomicTechnique()));
			}
		}

		chart.getData().add(coveredSeries);
		chart.getData().add(uncoveredSeries);
	}

	private void tacticThenPlatform(String selectedTactic)
	{
		XYChart.Series<String, Number> coveredSeries = new XYChart.Series<>();
		coveredSeries.setName(COVERED);

		XYChart.Series<String, Number> uncoveredSeries = new XYChart.Series<>();
		uncoveredSeries.setName(UNCOVERED);

		DataTree selectedTree;

		if (selectedTactic.equals(ALL))
		{
			Triple tripleValue;
			for (String platform : Constants.PLATFORMS)
			{
				path[2] = platform;
				int mitreTotal = 0, atomicTechnique = 0;
				for (int i = 0; i < 3; ++i)
				{
					path[0] = Constants.DOMAINS[i];
					if (i == 0)
					{
						selectedTree = enterpriseTree;
					}
					else if (i == 1)
					{
						selectedTree = mobileTree;
					}
					else
					{
						selectedTree = icsTree;
					}

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
				for (int i = 0; i < 3; ++i)
				{
					path[0] = Constants.DOMAINS[i];
					if (i == 0)
					{
						selectedTree = enterpriseTree;
					}
					else if (i == 1)
					{
						selectedTree = mobileTree;
					}
					else
					{
						selectedTree = icsTree;
					}
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

		chart.getData().add(coveredSeries);
		chart.getData().add(uncoveredSeries);
	}

	private void platformThenTactic(String selectedPlatform)
	{
		XYChart.Series<String, Number> coveredSeries = new XYChart.Series<>();
		coveredSeries.setName(COVERED);

		XYChart.Series<String, Number> uncoveredSeries = new XYChart.Series<>();
		uncoveredSeries.setName(UNCOVERED);

		DataTree selectedTree;

		if (selectedPlatform.equals(ALL))
		{
			Triple tripleValue;
			for (String tactic : Constants.TACTICS)
			{
				path[1] = tactic;
				int mitreTotal = 0, atomicTechnique = 0;
				for (int i = 0; i < 3; ++i)
				{
					path[0] = Constants.DOMAINS[i];
					if (i == 0)
					{
						selectedTree = enterpriseTree;
					}
					else if (i == 1)
					{
						selectedTree = mobileTree;
					}
					else
					{
						selectedTree = icsTree;
					}
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
				for (int i = 0; i < 3; ++i)
				{
					path[0] = Constants.DOMAINS[i];
					if (i == 0)
					{
						selectedTree = enterpriseTree;
					}
					else if (i == 1)
					{
						selectedTree = mobileTree;
					}
					else
					{
						selectedTree = icsTree;
					}
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

		chart.getData().add(coveredSeries);
		chart.getData().add(uncoveredSeries);
	}

	private void platformThenDomain(String selectedPlatform)
	{
		XYChart.Series<String, Number> coveredSeries = new XYChart.Series<>();
		coveredSeries.setName(COVERED);

		XYChart.Series<String, Number> uncoveredSeries = new XYChart.Series<>();
		uncoveredSeries.setName(UNCOVERED);

		if (selectedPlatform.equals(ALL))
		{
			for (int i = 0; i < 3; ++i)
			{
				path[0] = Constants.DOMAINS[i];
				Triple tripleValue;
				if (i == 0)
				{
					tripleValue = (Triple) enterpriseTree.getValue(Arrays.copyOfRange(path, 0, 1));
				}
				else if (i == 1)
				{
					tripleValue = (Triple) mobileTree.getValue(Arrays.copyOfRange(path, 0, 1));
				}
				else
				{
					tripleValue = (Triple) icsTree.getValue(Arrays.copyOfRange(path, 0, 1));
				}
				coveredSeries.getData()
						.add(new XYChart.Data<>(path[0], tripleValue.getAtomicNode().getAtomicTechnique()));
				uncoveredSeries.getData().add(new XYChart.Data<>(path[0],
						tripleValue.getMitreNode() - tripleValue.getAtomicNode().getAtomicTechnique()));
			}
		}
		else
		{
			path[2] = selectedPlatform;
			for (int i = 0; i < 3; ++i)
			{
				path[0] = Constants.DOMAINS[i];
				int mitreTotal = 0, atomicTechnique = 0;
				for (String tactic : Constants.TACTICS)
				{
					path[1] = tactic;
					Triple tripleValue;
					if (i == 0)
					{
						tripleValue = (Triple) enterpriseTree.getValue(Arrays.copyOfRange(path, 0, 3));
					}
					else if (i == 1)
					{
						tripleValue = (Triple) mobileTree.getValue(Arrays.copyOfRange(path, 0, 3));
					}
					else
					{
						tripleValue = (Triple) icsTree.getValue(Arrays.copyOfRange(path, 0, 3));
					}

					mitreTotal += tripleValue.getMitreNode();
					atomicTechnique += tripleValue.getAtomicNode().getAtomicTechnique();
				}
				coveredSeries.getData().add(new XYChart.Data<>(path[0], atomicTechnique));
				uncoveredSeries.getData().add(new XYChart.Data<>(path[0], mitreTotal - atomicTechnique));
			}
		}

		chart.getData().add(coveredSeries);
		chart.getData().add(uncoveredSeries);
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
		DataTree selectedTree;
		Triple selectedNode;
		int numMitreTechnique = 0, numAtomicTechnique = 0, numAtomicTest = 0;

		if (secondChoice.equals(ALL))
		{
			for (int i = 0; i < 3; ++i)
			{
				path[0] = Constants.DOMAINS[i];

				if (i == 0)
				{
					selectedTree = enterpriseTree;
				}
				else if (i == 1)
				{
					selectedTree = mobileTree;
				}
				else
				{
					selectedTree = icsTree;
				}
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
				if (secondChoice.equals(Constants.DOMAINS[0]))
				{
					selectedTree = enterpriseTree;
				}
				else if (secondChoice.equals(Constants.DOMAINS[1]))
				{
					selectedTree = mobileTree;
				}
				else
				{
					selectedTree = icsTree;
				}

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
				for (int i = 0; i < 3; ++i)
				{
					path[0] = Constants.DOMAINS[i];

					if (i == 0)
					{
						selectedTree = enterpriseTree;
					}
					else if (i == 1)
					{
						selectedTree = mobileTree;
					}
					else
					{
						selectedTree = icsTree;
					}
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
				for (int i = 0; i < 3; ++i)
				{
					path[0] = Constants.DOMAINS[i];

					if (i == 0)
					{
						selectedTree = enterpriseTree;
					}
					else if (i == 1)
					{
						selectedTree = mobileTree;
					}
					else
					{
						selectedTree = icsTree;
					}
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
		// Capture the screen image
		WritableImage image = screenBorder.snapshot(null, null);

		FileChooser fileChooser = new FileChooser();
		fileChooser.setTitle("Save Chart Image");
		fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("PNG Image", "*.png"));

		File file = fileChooser.showSaveDialog(saveButton.getScene().getWindow());
		if (file != null)
		{
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