module com.example.cryptography {
    requires javafx.controls;
    requires javafx.fxml;

    requires org.controlsfx.controls;
    requires org.kordamp.bootstrapfx.core;
    requires org.bouncycastle.provider;
    requires com.fasterxml.jackson.databind;

    opens com.example.cryptography to javafx.fxml;
    exports com.example.cryptography;
}