import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Scanner;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class backend {
    public ArrayList<String> getUserFiles(String user) {
        ArrayList<String> userFiles = new ArrayList<String>();
        File userDir = new File("data/" + user);
        String scans[] = userDir.list();
        for (String scan : scans) {
            userFiles.add(scan);
        }
        return userFiles;
    }

    public static boolean loginUser(String user, String password) {
        try {
            File hashFile = new File("data/" + user + "/" + "password.dat");
            Scanner reader = new Scanner(hashFile);
            String hashed = reader.nextLine();
            reader.close();
            if(hashed.compareTo(hasher(password)) == 0){
                return true;
            } else
                return false;
        } catch (Exception e) {
            System.out.println("User Not Found!" + e.toString());
            return false;
        }
    }

    public static String hasher(String input) throws NoSuchAlgorithmException {
        MessageDigest mD = MessageDigest.getInstance("SHA-256");
        byte[] result = mD.digest(input.getBytes());
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < result.length; i++) {
            sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1));
        }
        return sb.toString();
    }

    public static String encryptionString(String user, String password){
        return user + "_" + password + "_";
    }

    public static byte[] AESer(String input, String password, int choice) {
        String salt = "guisreallyreallydosuck"; 
        try{
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey keySpec = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            AlgorithmParameters params = cipher.getParameters();
            byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();

            byte[] output;

            if (choice == 0){
                cipher.init(Cipher.ENCRYPT_MODE, keySpec);
                output = cipher.doFinal(input.getBytes());
                String str = new String(output, StandardCharsets.UTF_8);
                System.out.print(str);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
                output = cipher.doFinal(input.getBytes());
            }

            return output;
        } catch (Exception e) {
            System.out.println(e);
            return e.getMessage().getBytes();
        }
    }

    public static byte[] AESer(byte[] input, String password, int choice) {
        String salt = "guisreallyreallydosuck"; 
        try{
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey keySpec = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            AlgorithmParameters params = cipher.getParameters();
            byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();

            byte[] output;

            if (choice == 0){
                cipher.init(Cipher.ENCRYPT_MODE, keySpec);
                output = cipher.doFinal(input);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
                output = cipher.doFinal(input);
            }
            return output;
        } catch (Exception e) {
            System.out.println(e);
            return e.getMessage().getBytes();
        }
    }

    public static byte[] runNmap(String commands){
        try {
            Process executor = Runtime.getRuntime().exec("nmap " + commands);
            InputStream in = executor.getInputStream();
            byte[] byteBuffer = new byte[8000];
            int bytesRead = 0;

            ByteArrayOutputStream bufferPrime = new ByteArrayOutputStream();

            while((bytesRead = in.read(byteBuffer)) != -1) {
                bufferPrime.write(byteBuffer, 0, bytesRead);
            }

            byte[] data = bufferPrime.toByteArray();

            return data;

        } catch (Exception e) {
            return new byte[]{'e', 'r', 'r', 'o','r'};
        }
    }

    public static boolean saveScanToFile(String user, byte[] encryptedData){
        try {
            String timeStamp = new SimpleDateFormat("yyyyMMddHHmm'.txt'").format(new Date());
            File toSave = new File("data/" + user + "/" + timeStamp);
            if(toSave.createNewFile()){
                OutputStream writer = new FileOutputStream(toSave); 
                writer.write(encryptedData);
                writer.close();
                return true;
            } else return false;
        } catch (Exception e){
            return false;
        }
    }

    public static String readFromFile(String fileName, String user) throws FileNotFoundException {
        try {
            File hashFile = new File("data/" + user + "/" + "password.dat");
            Scanner reader = new Scanner(hashFile);
            StringBuilder tmpSB = new StringBuilder();
            do{
                tmpSB.append(reader.nextLine());
            } while(reader.nextLine() != null);
            reader.close();
            return tmpSB.toString();
        } catch (Exception e) {
            return null;
        }
    }

    public static String makeReadable(String dumpedText){
        String internals = "Welcome to the easy to read output section! \n\n";
        String[] eachLine = dumpedText.split("\n");
        if(dumpedText.contains("/tcp") || dumpedText.contains("/udp")) {
            internals += "Open Ports (An open port can be connected to freely without issue): \n";
            for(int i = 0; i < eachLine.length; i++){
                if(eachLine[i].contains("open")){
                    internals += eachLine[i] + "\n";
                }
            }
            internals += "\n Filtered Ports (A filtered port is blocked by a software/hardware firewall and/or filter):\n ";
            for(int i = 0; i < eachLine.length; i++){
                if(eachLine[i].contains("filtered")){
                    internals += eachLine[i] + "\n";
                }
            }
            internals += "\n";
            for(int i = 0; i < eachLine.length; i++){
                if(eachLine[i].contains("closed")){
                    internals += eachLine[i] + "\n";
                }
            }
        } else {
            internals += "\n Not enough info to provide a broken down output section. \n";
        }
        return internals;
    }

    public static boolean isAdminGroup(String user){
        String[] database = {"user1", "tester"};
        for(int i = 0; i < database.length; i++){
            if (database[i].compareTo(user) == 0){
                return true;
            }
        }
        return false;
    }
}
