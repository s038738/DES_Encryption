
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;







import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Scanner;
import java.util.stream.Stream;

public class MainFrame extends JFrame {
    private JTextField textField1;
    private JTextField textField2;
    private JButton encryptButton;
    private JButton decryptButton;
    private JRadioButton ECBRadioButton;
    private JRadioButton CBCRadioButton;
    private JLabel MessageLabel;
    private JLabel TextLabel;
    private JPanel mainPanel;
    private JButton fileEncryptButton;
    private JButton fileDecryptButton;
    private JTextField textField3;

    private String text;
    private String key;
    private int choise;




    public MainFrame(){
        setContentPane(mainPanel);
        setSize(400,400);
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        setVisible(true);
        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                text = textField1.getText();
                key = textField2.getText();

                try (PrintStream out = new PrintStream(new FileOutputStream("D:\\VIKO\\4sem\\IS\\2\\src\\original.txt"))) {
                    out.print(text);
                }catch (Exception exep){
                    exep.printStackTrace();
                }

                try {
                    System.out.println("Encryption text");

                    FileInputStream fis = new FileInputStream("D:\\VIKO\\4sem\\IS\\2\\src\\original.txt");
                    FileOutputStream fos = new FileOutputStream("D:\\VIKO\\4sem\\IS\\2\\src\\encrypted.txt");
                    encrypt(key, fis, fos);

                } catch (Throwable ex) {
                    ex.printStackTrace();
                }




                FileInputStream stream = null;
                try {
                    stream = new FileInputStream("D:\\VIKO\\4sem\\IS\\2\\src\\encrypted.txt");
                } catch (FileNotFoundException ex) {
                    ex.printStackTrace();
                }
                try {
                    Reader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.ISO_8859_1));
                    StringBuilder builder = new StringBuilder();
                    char[] buffer = new char[8192];
                    int read;
                    while ((read = reader.read(buffer, 0, buffer.length)) > 0) {
                        builder.append(buffer, 0, read);
                    }
                   String text2 =  builder.toString();
                    //System.out.println(text2);
                    textField3.setText(text2);
                } catch (IOException exception) {
                    exception.printStackTrace();
                } finally {
                    // Potential issue here: if this throws an IOException,
                    // it will mask any others. Normally I'd use a utility
                    // method which would log exceptions and swallow them
                    try {
                        stream.close();
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }
                }






            }
        });
        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                text = textField1.getText();
                key = textField2.getText();

                try (PrintStream out = new PrintStream(new FileOutputStream("D:\\VIKO\\4sem\\IS\\2\\src\\encrypted.txt"))) {
                    out.print(text);
                }catch (Exception exep){
                    exep.printStackTrace();
                }

                try {
                    System.out.println("Decryption text");
                    FileInputStream fis2 = new FileInputStream("D:\\VIKO\\4sem\\IS\\2\\src\\encrypted.txt");
                    FileOutputStream fos2 = new FileOutputStream("D:\\VIKO\\4sem\\IS\\2\\src\\decrypted.txt");
                    decrypt(key, fis2, fos2);

                } catch (Throwable ex) {
                    ex.printStackTrace();
                }

                FileInputStream stream = null;
                try {
                    stream = new FileInputStream("D:\\VIKO\\4sem\\IS\\2\\src\\decrypted.txt");
                } catch (FileNotFoundException ex) {
                    ex.printStackTrace();
                }
                try {
                    Reader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.ISO_8859_1));
                    StringBuilder builder = new StringBuilder();
                    char[] buffer = new char[8192];
                    int read;
                    while ((read = reader.read(buffer, 0, buffer.length)) > 0) {
                        builder.append(buffer, 0, read);
                    }
                    String text2 =  builder.toString();
                    //System.out.println(text2);
                    textField3.setText(text2);
                } catch (IOException exception) {
                    exception.printStackTrace();
                } finally {
                    // Potential issue here: if this throws an IOException,
                    // it will mask any others. Normally I'd use a utility
                    // method which would log exceptions and swallow them
                    try {
                        stream.close();
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }
                }

            }
        });
        fileEncryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                key = textField2.getText();
                try {
                    System.out.println("Encryption file");
                    FileInputStream fis = new FileInputStream("D:\\VIKO\\4sem\\IS\\2\\src\\original.txt");
                    FileOutputStream fos = new FileOutputStream("D:\\VIKO\\4sem\\IS\\2\\src\\encrypted.txt");
                    encrypt(key, fis, fos);
                    MessageLabel.setText("Encryption Done");
                } catch (Throwable ex) {
                    ex.printStackTrace();
                }
            }
        });
        fileDecryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                key = textField2.getText();
                try {
                    System.out.println("Decryption file");
                    FileInputStream fis2 = new FileInputStream("D:\\VIKO\\4sem\\IS\\2\\src\\encrypted.txt");
                    FileOutputStream fos2 = new FileOutputStream("D:\\VIKO\\4sem\\IS\\2\\src\\decrypted.txt");
                    decrypt(key, fis2, fos2);
                    MessageLabel.setText("Decryption Done");
                } catch (Throwable ex) {
                    ex.printStackTrace();
                }
            }
        });
    }

    public static void encrypt(String key, InputStream is, OutputStream os) throws Throwable {
        encryptOrDecrypt(key, Cipher.ENCRYPT_MODE, is, os);
    }

    public static void decrypt(String key, InputStream is, OutputStream os) throws Throwable {
        encryptOrDecrypt(key, Cipher.DECRYPT_MODE, is, os);
    }

    public static void encryptOrDecrypt(String key, int mode, InputStream is, OutputStream os) throws Throwable {

        DESKeySpec dks = new DESKeySpec(key.getBytes());
        SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
        SecretKey desKey = skf.generateSecret(dks);
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding"); // DES/ECB/PKCS5Padding for SunJCE

        if (mode == Cipher.ENCRYPT_MODE) {
            cipher.init(Cipher.ENCRYPT_MODE, desKey);
            CipherInputStream cis = new CipherInputStream(is, cipher);
            doCopy(cis, os);
        } else if (mode == Cipher.DECRYPT_MODE) {
            cipher.init(Cipher.DECRYPT_MODE, desKey);
            CipherOutputStream cos = new CipherOutputStream(os, cipher);
            doCopy(is, cos);
        }
    }

    public static void doCopy(java.io.InputStream is, OutputStream os) throws IOException {
        byte[] bytes = new byte[64];
        int numBytes;
        while ((numBytes = is.read(bytes)) != -1) {
            os.write(bytes, 0, numBytes);
        }
        os.flush();
        os.close();
        is.close();
        System.out.println("Done");
    }

}
