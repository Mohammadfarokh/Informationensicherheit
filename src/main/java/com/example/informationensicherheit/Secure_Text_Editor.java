package com.example.informationensicherheit;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.BorderPane;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.util.encoders.Hex;

public class Secure_Text_Editor extends Application {
    private TextArea textArea;
    private File currentFile;
    private AesEncryption aesEncryption;
    private String paddingMethod;
    private String blockModes;
    private ChaCha20Encryption chaCha20Encryption;
    byte[] keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f"
            + "000102030405060708090a0b0c0d0e0f");

    /**
     * The main method that launches the application.
     */
    public static void main(String[] args)  {
     /*   Security.addProvider(new BouncyCastleProvider());

        Provider[] providers = Security.getProviders();

        for (Provider provider : providers) {
            System.out.println(provider.getName());
        }*/
        launch(args);
    }

    /**
     * Initializes the primary stage and sets up the user interface.
     *
     * @param primaryStage The primary stage of the application
     * @throws NoSuchAlgorithmException Thrown when a particular cryptographic algorithm is requested but is not available in the environment
     * @throws FileNotFoundException Thrown if the specified file is not found during initialization
     */
    @Override
    public void start(Stage primaryStage) throws NoSuchAlgorithmException, FileNotFoundException {
        primaryStage.setTitle("Simple Text Editor");

        textArea = new TextArea();
        BorderPane layout = new BorderPane();
        layout.setCenter(textArea);
        //"PKCS7"., "ISO7816-4", "ISO10126-2", "PKCS5Padding", "PKCS7Padding", "TBC", "X9.23", "NoPadding"
        this.paddingMethod = "PKCS7Padding";
        //"CBC", "CTS", "CTR", "CFB", "OFB"
        this.blockModes = "CTR";
        aesEncryption = new AesEncryption(paddingMethod, blockModes);
        chaCha20Encryption = new ChaCha20Encryption(keyBytes);

        MenuBar menuBar = new MenuBar();
        Menu fileMenu = new Menu("File");
        MenuItem newMenuItem = new MenuItem("New");
        MenuItem openMenuItem = new MenuItem("Open");
        MenuItem saveMenuItem = new MenuItem("Save");
        MenuItem encryptMenuItem = new MenuItem("Encrypt");
        MenuItem decryptMenuItem = new MenuItem("Decrypt");
        MenuItem encryptChaCha20 = new MenuItem("Encrypt with ChaCha20");
        MenuItem decryptChaCha20 = new MenuItem("Decrypt with ChaCha20");
        MenuItem exitMenuItem = new MenuItem("Exit");

        fileMenu.getItems().addAll(newMenuItem, openMenuItem, saveMenuItem,encryptMenuItem,
                decryptMenuItem, encryptChaCha20, decryptChaCha20, exitMenuItem);
        menuBar.getMenus().add(fileMenu);
        /**
         * Creates a new document by clearing the text area and resetting the current file.
         */
        newMenuItem.setOnAction(e -> newDocument());
        /**
         * Opens an existing document using a file chooser dialog.
         */
        openMenuItem.setOnAction(e -> openDocument());
        /**
         * Saves the current document to a file.
         */
        saveMenuItem.setOnAction(e -> saveDocument());
        /**
         * Encrypts the current document using AES encryption.
         */
        encryptMenuItem.setOnAction(e -> encryptDocument());
        /**
         * Decrypts the current document using AES decryption.
         */
        decryptMenuItem.setOnAction(e -> decryptDocument());

         /* Encrypts the current document using ChaCha20 encryption.
                */
        encryptChaCha20.setOnAction(e -> {
            try {
                encryptDocumentWithChaCha20();
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
        /**
         * Decrypts the current document using ChaCha20 decryption.
         */
        decryptChaCha20.setOnAction(e -> {
            try {
                decryptDocumentChaCha20();
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
        /**
         * Exits the application.
         */
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

     private void encryptDocumentWithChaCha20() throws Exception {
        String plainText = textArea.getText();
        String encryptedText = chaCha20Encryption.encrypt(plainText);
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

    private void decryptDocumentChaCha20() throws Exception {
        String encryptedText = textArea.getText();
        String decryptedText =  chaCha20Encryption.decrypt(encryptedText);
        if (decryptedText != null) {
            textArea.setText(decryptedText);
        }
    }
}

