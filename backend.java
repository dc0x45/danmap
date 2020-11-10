import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
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

    public static String encryptor(String toEncrypt, String password) {
        String salt = "guisreallyreallydosuck"; 
        try{
            byte[] iv = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'};
            IvParameterSpec ivspec = new IvParameterSpec(iv);
            
            SecretKeyFactory sFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec specifications = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);

            SecretKey middleMan = sFactory.generateSecret(specifications);
            SecretKeySpec secretKey = new SecretKeySpec(middleMan.getEncoded(), "AES");
            
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);

            return Base64.getEncoder().encodeToString(cipher.doFinal(toEncrypt.getBytes("UTF-8")));
        } catch (Exception e) {
            System.out.println(e);
        } return null;
    }

    public static String decryptor (String toDecrypt, String password) {
        String salt = "guisreallyreallydosuck"; 
        try {
            byte[] iv = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'};
            IvParameterSpec ivspec = new IvParameterSpec(iv);
            
            SecretKeyFactory sFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec specifications = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);

            SecretKey middleMan = sFactory.generateSecret(specifications);
            SecretKeySpec secretKey = new SecretKeySpec(middleMan.getEncoded(), "AES");
            
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);

            return new String(cipher.doFinal(Base64.getDecoder().decode(toDecrypt)));
        } catch (Exception e) {
            System.out.println(e);
        } return null;
    }


 
    public static StringBuilder runNmap(String commands){
        StringBuilder sb = new StringBuilder("Danmap v1.0\n");
        try {
            Process executor = Runtime.getRuntime().exec("nmap" + commands);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(executor.getInputStream()));
            String singleLine;
            while ((singleLine = reader.readLine()) != null) {
                System.out.println(singleLine);
                sb.append(singleLine);
            }
            reader.close();
            return sb;
        } catch (Exception e) {
            sb.append(e);
            return sb;
        }
    }

    public static boolean saveScanToFile(String user, String encryptedData){
        try {
            String timeStamp = new SimpleDateFormat("yyyyMMddHHmm'.txt'").format(new Date());
            File toSave = new File("data/" + user + "/" + timeStamp);
            if(toSave.createNewFile()){
                FileWriter writer = new FileWriter(toSave);
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

    public static HashMap<String, String> makeReadable(StringBuilder dumpedText){
        HashMap<String, String> internals = new HashMap<String, String>();
        
        return internals;
    }

}
