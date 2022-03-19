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
import javax.crypto.spec.IvParameterSpec;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

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
    private JRadioButton PCBCRadioButton;
    private JRadioButton CFBRadioButton;
    private JRadioButton OFBRadioButton;
    private String text;
    private String key;
    private static String choice;

    public MainFrame(){
        setContentPane(mainPanel);
        setSize(400,400);
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        setVisible(true);
        ECBRadioButton.setSelected(true);
        choice = "DES/ECB/PKCS5Padding";

        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                text = textField1.getText();
                key = textField2.getText();

                File fileOriginal = new File("original.txt");
                String pathOriginal = fileOriginal.getAbsolutePath();
                File fileEncrypted = new File("encrypted.txt");
                String pathEncrypted = fileEncrypted.getAbsolutePath();

                try (PrintStream out = new PrintStream(new FileOutputStream(pathOriginal))) {
                    out.print(text);
                }catch (Exception exep){
                    System.out.println(exep.getMessage());
                }
                    try {
                        System.out.println(choice + " Encryption");
                        FileInputStream fis = new FileInputStream(pathOriginal);
                        FileOutputStream fos = new FileOutputStream(pathEncrypted);
                        encrypt(key, fis, fos);
                    } catch (Throwable ex) {
                        System.out.println(ex.getMessage());
                    }

                FileInputStream stream = null;
                try {
                    stream = new FileInputStream(pathEncrypted);
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
                    textField3.setText(text2);
                } catch (IOException exception) {
                    System.out.println(exception.getMessage());
                } finally {
                    try {
                        stream.close();
                    } catch (IOException ex) {
                        System.out.println(ex.getMessage());
                    }
                }
            }
        });
        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                text = textField1.getText();
                key = textField2.getText();

                File fileEncrypted = new File("encrypted.txt");
                String pathEncrypted = fileEncrypted.getAbsolutePath();
                File fileDecrypted = new File("decrypted.txt");
                String pathDecrypted = fileDecrypted.getAbsolutePath();

//                try (PrintStream out = new PrintStream(new FileOutputStream("D:\\VIKO\\4sem\\IS\\2\\src\\ecrypted2.txt"))) {
//                    out.print(text);
//                }catch (Exception exep){
//                    exep.printStackTrace();
//                }
                    try {
                        System.out.println(choice + " Decryption");

                        FileInputStream fis2 = new FileInputStream(pathEncrypted);
                        FileOutputStream fos2 = new FileOutputStream(pathDecrypted);
                        decrypt(key, fis2, fos2);
                    } catch (Throwable ex) {
                        System.out.println(ex.getMessage());
                    }

                FileInputStream stream = null;
                try {
                    stream = new FileInputStream(pathDecrypted);
                } catch (FileNotFoundException ex) {
                    System.out.println(ex.getMessage());
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
                    textField3.setText(text2);
                } catch (IOException exception) {
                    System.out.println(exception.getMessage());
                } finally {
                    try {
                        stream.close();
                    } catch (IOException ex) {
                        System.out.println(ex.getMessage());
                    }
                }
            }
        });
        fileEncryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                key = textField2.getText();

                File fileOriginal = new File("original.txt");
                String pathOriginal = fileOriginal.getAbsolutePath();
                File fileEncrypted = new File("encrypted.txt");
                String pathEncrypted = fileEncrypted.getAbsolutePath();

                    try {
                        System.out.println(choice);

                        FileInputStream fis = new FileInputStream(pathOriginal);
                        FileOutputStream fos = new FileOutputStream(pathEncrypted);
                        encrypt(key, fis, fos);
                        MessageLabel.setText("Encryption done");
                    } catch (Throwable ex) {
                        ex.printStackTrace();
                    }
            }
        });
        fileDecryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                key = textField2.getText();

                File fileEncrypted = new File("encrypted.txt");
                String pathEncrypted = fileEncrypted.getAbsolutePath();
                File fileDecrypted = new File("decrypted.txt");
                String pathDecrypted = fileDecrypted.getAbsolutePath();

                    try {
                        System.out.println(choice);
                        FileInputStream fis2 = new FileInputStream(pathEncrypted);
                        FileOutputStream fos2 = new FileOutputStream(pathDecrypted);
                        decrypt(key, fis2, fos2);
                        MessageLabel.setText("Decryption Done");
                    } catch (Throwable ex) {
                        ex.printStackTrace();
                    }
            }
        });
        ECBRadioButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                CBCRadioButton.setSelected(false);
                PCBCRadioButton.setSelected(false);
                CFBRadioButton.setSelected(false);
                OFBRadioButton.setSelected(false);
                ECBRadioButton.setSelected(true);
                choice = "DES/ECB/PKCS5Padding";
            }
        });
        CBCRadioButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                CBCRadioButton.setSelected(true);
                PCBCRadioButton.setSelected(false);
                CFBRadioButton.setSelected(false);
                OFBRadioButton.setSelected(false);
                ECBRadioButton.setSelected(false);
                choice = "DES/CBC/PKCS5Padding";
            }
        });
        PCBCRadioButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                CBCRadioButton.setSelected(false);
                ECBRadioButton.setSelected(false);
                PCBCRadioButton.setSelected(true);
                CFBRadioButton.setSelected(false);
                OFBRadioButton.setSelected(false);
                choice = "DES/PCBC/PKCS5Padding";
            }
        });
        CFBRadioButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                CBCRadioButton.setSelected(false);
                ECBRadioButton.setSelected(false);
                PCBCRadioButton.setSelected(false);
                CFBRadioButton.setSelected(true);
                OFBRadioButton.setSelected(false);
                choice = "DES/CFB/PKCS5Padding";
            }
        });
        OFBRadioButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                CBCRadioButton.setSelected(false);
                ECBRadioButton.setSelected(false);
                PCBCRadioButton.setSelected(false);
                CFBRadioButton.setSelected(false);
                OFBRadioButton.setSelected(true);
                choice = "DES/OFB/PKCS5Padding";
            }
        });
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
    public static void encryptOrDecrypt(String key, int mode, InputStream is, OutputStream os) throws Throwable {
        DESKeySpec dks = new DESKeySpec(key.getBytes());
        SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
        SecretKey desKey = skf.generateSecret(dks);
        Cipher cipher = Cipher.getInstance(choice);
        byte[] ivBytes = new byte[8];
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        if (mode == Cipher.ENCRYPT_MODE) {
            cipher.init(Cipher.ENCRYPT_MODE, desKey, iv);
            CipherInputStream cis = new CipherInputStream(is, cipher);
            doCopy(cis, os);
        } else if (mode == Cipher.DECRYPT_MODE) {
            cipher.init(Cipher.DECRYPT_MODE, desKey, iv);
            CipherOutputStream cos = new CipherOutputStream(os, cipher);
            doCopy(is, cos);
        }
    }
    public static void encrypt(String key, InputStream is, OutputStream os) throws Throwable {
        if (Objects.equals(choice, "DES/ECB/PKCS5Padding")){
            encryptOrDecryptECB(key, Cipher.ENCRYPT_MODE, is, os);
        }else{
            encryptOrDecrypt(key, Cipher.ENCRYPT_MODE, is, os);
        }
    }
    public static void decrypt(String key, InputStream is, OutputStream os) throws Throwable {
        if (Objects.equals(choice, "DES/ECB/PKCS5Padding")){
            encryptOrDecryptECB(key, Cipher.DECRYPT_MODE, is, os);
        }else{
            encryptOrDecrypt(key, Cipher.DECRYPT_MODE, is, os);
        }
    }

    public static void encryptOrDecryptECB(String key, int mode, InputStream is, OutputStream os) throws Throwable {
        DESKeySpec dks = new DESKeySpec(key.getBytes());
        SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
        SecretKey desKey = skf.generateSecret(dks);
        Cipher cipher = Cipher.getInstance(choice);
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









}