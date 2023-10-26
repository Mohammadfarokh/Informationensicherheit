module com.example.informationensicherheit {
    requires javafx.controls;
    requires javafx.fxml;

    requires org.controlsfx.controls;
    requires org.kordamp.bootstrapfx.core;

    opens com.example.informationensicherheit to javafx.fxml;
    exports com.example.informationensicherheit;
}