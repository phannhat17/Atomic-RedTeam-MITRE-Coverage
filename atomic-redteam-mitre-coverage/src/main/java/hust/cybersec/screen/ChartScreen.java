package hust.cybersec.screen;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;

public class ChartScreen extends Application {
    @Override
    public void start(Stage stage) throws IOException {
        FXMLLoader fxmlLoader = new FXMLLoader(ChartScreen.class.getResource("chart.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 1200, 800);
        stage.setTitle("Interactive StackedBar Chart");
        stage.setScene(scene);
        stage.setMaximized(true);
        stage.show();
    }

    public static void LaunchScene() {
        launch();
    }
}