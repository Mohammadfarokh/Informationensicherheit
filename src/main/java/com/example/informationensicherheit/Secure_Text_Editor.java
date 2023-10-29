package com.example.informationensicherheit;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.BorderPane;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Secure_Text_Editor extends Application {
    private TextArea textArea;
    private File currentFile;
    private AesEncryption aesEncryption;
    private String paddingMethod;

    public static void main(String[] args)  {
     /*   Security.addProvider(new BouncyCastleProvider());

        Provider[] providers = Security.getProviders();

        for (Provider provider : providers) {
            System.out.println(provider.getName());
        }*/
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) throws NoSuchAlgorithmException, FileNotFoundException {
        primaryStage.setTitle("Simple Text Editor");

        textArea = new TextArea();
        BorderPane layout = new BorderPane();
        layout.setCenter(textArea);
        //"PKCS7"., "ISO7816-4", "ISO10126-2", "PKCS5Padding", "PKCS7Padding", "TBC", "X9.23", "NoPadding"
        this.paddingMethod = "PKCS7Padding";
        aesEncryption = new AesEncryption(paddingMethod);

        MenuBar menuBar = new MenuBar();
        Menu fileMenu = new Menu("File");
        MenuItem newMenuItem = new MenuItem("New");
        MenuItem openMenuItem = new MenuItem("Open");
        MenuItem saveMenuItem = new MenuItem("Save");
        MenuItem encryptMenuItem = new MenuItem("Encrypt");
        MenuItem decryptMenuItem = new MenuItem("Decrypt");
        MenuItem exitMenuItem = new MenuItem("Exit");

        fileMenu.getItems().addAll(newMenuItem, openMenuItem, saveMenuItem,encryptMenuItem,
                decryptMenuItem, exitMenuItem);
        menuBar.getMenus().add(fileMenu);

        newMenuItem.setOnAction(e -> newDocument());
        openMenuItem.setOnAction(e -> openDocument());
        saveMenuItem.setOnAction(e -> saveDocument());
        encryptMenuItem.setOnAction(e -> encryptDocument());
        decryptMenuItem.setOnAction(e -> decryptDocument());
        exitMenuItem.setOnAction(e -> primaryStage.close());

        layout.setTop(menuBar);

        Scene scene = new Scene(layout, 600, 400);
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    private void newDocument() {
        textArea.clear();
        currentFile = null;
    }

    private void openDocument() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Text Files", "*.txt"));
        File file = fileChooser.showOpenDialog(null);
        if (file != null) {
            currentFile = file;
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                StringBuilder content = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    content.append(line).append("\n");
                }
                textArea.setText(content.toString());
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private void saveDocument() {
        if (currentFile == null) {
            FileChooser fileChooser = new FileChooser();
            fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Text Files", "*.txt"));
            File file = fileChooser.showSaveDialog(null);
            if (file != null) {
                currentFile = file;
            } else {
                return;
            }
        }

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(currentFile))) {
            writer.write(textArea.getText());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void encryptDocument() {
        String plainText = textArea.getText();
        String encryptedText = aesEncryption.encrypt(plainText);
        if (encryptedText != null) {
            textArea.setText(encryptedText);
        }
    }

    private void decryptDocument() {
        String encryptedText = textArea.getText();
        String decryptedText = aesEncryption.decrypt(encryptedText);
        if (decryptedText != null) {
            textArea.setText(decryptedText);
        }
    }
}

