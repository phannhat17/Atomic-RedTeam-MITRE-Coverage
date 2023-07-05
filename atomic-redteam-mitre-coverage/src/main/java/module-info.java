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

    opens hust.cybersec.screen to javafx.fxml;
    opens hust.cybersec.data.process to com.fasterxml.jackson.databind;
    exports hust.cybersec.screen;
}