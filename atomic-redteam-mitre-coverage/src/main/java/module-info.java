module hust.cybersec.atomicdatacollector {
    requires javafx.controls;
    requires javafx.fxml;
    requires com.fasterxml.jackson.databind;
    requires com.fasterxml.jackson.dataformat.yaml;
    requires org.yaml.snakeyaml;
    requires org.apache.poi.poi;
    requires org.apache.poi.ooxml;
    requires java.desktop;
    requires javafx.swing;
    requires java.logging;

    opens hust.cybersec.functional.chart to javafx.fxml;
    exports hust.cybersec.functional.chart;
    opens hust.cybersec.data.process.structure to com.fasterxml.jackson.databind;
    opens hust.cybersec.data.process.conversion to com.fasterxml.jackson.databind;
    opens hust.cybersec.data.process.validation to com.fasterxml.jackson.databind;
}