package com.example.cryptography;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.BorderPane;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Optional;

import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Secure_Text_Editor extends Application {
    public TextArea textArea;
    public File currentFile;
    public AesEncryption aesEncryption;
    public String paddingMethod;
    public String blockModes;
    public ChaCha20Encryption chaCha20Encryption;
    public String validation;
    public byte[] keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f"
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
        MenuItem ecryptCCM = new MenuItem("Ecrypt with CCM");
        MenuItem decryptCCM = new MenuItem("Decrypt with CCM");
        MenuItem ecryptGCM = new MenuItem("Ecrypt with GCM");
        MenuItem decryptGCM = new MenuItem("Decrypt with GCM");
        MenuItem ecryptGCMScrypt = new MenuItem("Ecrypt with GCM Scrypt");
        MenuItem decryptGCMScrypt = new MenuItem("Decrypt with GCM Scrypt");
        MenuItem exitMenuItem = new MenuItem("Exit");

        fileMenu.getItems().addAll(newMenuItem, openMenuItem, saveMenuItem,encryptMenuItem,
                decryptMenuItem, encryptChaCha20, decryptChaCha20, exitMenuItem, ecryptGCM, decryptGCM, ecryptCCM,
                decryptCCM, ecryptGCMScrypt, decryptGCMScrypt);
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

        ecryptGCM.setOnAction(e -> {
            try {
                ecryptGCM();
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });

        decryptGCM.setOnAction(e -> {
            try {
                decryptGCM();
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
        ecryptCCM.setOnAction(e -> encryptDocumentCCM());
        decryptCCM.setOnAction(e -> decryptDocumentCCM());
        ecryptGCMScrypt.setOnAction(e -> encryptDocumentGCMScrypt());
        decryptGCMScrypt.setOnAction(e -> decryptDocumentGCMScrypt());

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

    private void showAlert(Alert.AlertType alertType, String title, String contentText) {
        Alert alert = new Alert(alertType);
        alert.setTitle(title);
        alert.setHeaderText(null); // You can set a header text if needed
        alert.setContentText(contentText);
        alert.showAndWait();
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
                    content.append(line);
                }
                textArea.setText(content.toString());
                if(!HashingComponent.verifyHash(String.valueOf(content), validation, "SHA-256")){
                    showAlert(Alert.AlertType.INFORMATION, "Bad Message", "This message was manipulated.");
                }
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
            validation = HashingComponent.generateSHA256(textArea.getText());
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

    private void ecryptGCM() throws Exception{
        String plainText = textArea.getText();
        byte[] gcmText = aesEncryption.encryptGCM(plainText);
        System.out.println("encript "+Arrays.toString(gcmText));
        String encryptedText = Hex.toHexString(gcmText);
        if (encryptedText != null) {
            textArea.setText(encryptedText);
        }
    }

    private void decryptGCM() throws Exception{
        byte[] gcmText = aesEncryption.decryptGCM();
        System.out.println("dencript "+Arrays.toString(gcmText));
        String decryptedText = Hex.toHexString(gcmText);
        if (decryptedText != null) {
            textArea.setText(decryptedText);
        }

    }


    /**
     * Encrypts the current document using CCM encryption with AAD.
     */
    private void encryptDocumentCCM() {
        // Get plaintext from the text area
        String plainText = textArea.getText();

        // Call the encryption method
        try {
            byte[] encryptedText = aesEncryption.ccmEncryptWithAAD(Strings.toByteArray(plainText));
            String encryptedHex = Hex.toHexString(encryptedText);
            textArea.setText(encryptedHex);
        } catch (Exception ex) {
            showAlert(Alert.AlertType.ERROR, "Encryption Error", "Error during CCM encryption.");
            ex.printStackTrace();
        }
    }

    /**
     * Decrypts the current document using CCM decryption with AAD.
     */
    private void decryptDocumentCCM() {
        // Get ciphertext from the text area
        String encryptedHex = textArea.getText();

        // Call the decryption method
        try {
            byte[] encryptedText = Hex.decode(encryptedHex);
            byte[] decryptedBytes = aesEncryption.ccmDecryptWithAAD( encryptedText);
            String decryptedText = new String(decryptedBytes);
            textArea.setText(decryptedText);
        } catch (Exception ex) {
            showAlert(Alert.AlertType.ERROR, "Decryption Error", "Error during CCM decryption.");
            ex.printStackTrace();
        }
    }
    //-------------------------------------------------
    /**
     * Displays a pop-up window to get the password from the user.
     *
     * @return The entered password or null if the user cancels.
     */
    private String getPasswordFromUser() {
        TextInputDialog dialog = new TextInputDialog();
        dialog.setTitle("Enter Password");
        dialog.setHeaderText(null);
        dialog.setContentText("Please enter the password:");

        Optional<String> result = dialog.showAndWait();
        return result.orElse(null);
    }

    /**
     * Encrypts the current document using AES-GCM-Scrypt encryption.
     */
    private void encryptDocumentGCMScrypt() {
        // Get plaintext from the text area
        String plainText = textArea.getText();

        // Get password from the user
        String password = getPasswordFromUser();
        if (password == null) {
            return; // User canceled password input
        }

        // Call the encryption method
        try {
            byte[] encryptedText = aesEncryption.encryptWithPasswordAES256GCMScrypt(plainText, password);
            String encryptedHex = Hex.toHexString(encryptedText);
            textArea.setText(encryptedHex);
        } catch (Exception ex) {
            showAlert(Alert.AlertType.ERROR, "Encryption Error", "Error during AES-GCM-Scrypt encryption.");
            ex.printStackTrace();
        }
    }

    /**
     * Decrypts the current document using AES-GCM-Scrypt decryption.
     */
    private void decryptDocumentGCMScrypt() {
        // Get ciphertext from the text area
        String encryptedHex = textArea.getText();

        // Get password from the user
        String password = getPasswordFromUser();
        if (password == null) {
            return; // User canceled password input
        }

        // Call the decryption method
        try {
            byte[] encryptedText = Hex.decode(encryptedHex);
            String decryptedText = aesEncryption.decryptWithPasswordAES256GCMScrypt(encryptedText, password);
            textArea.setText(decryptedText);
        } catch (Exception ex) {
            showAlert(Alert.AlertType.ERROR, "Decryption Error", "Error during AES-GCM-Scrypt decryption.");
            ex.printStackTrace();
        }
    }
}

