package org.example;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Objects;
import java.util.Properties;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class PGPencryption {

    public static Properties properties;
    public static String PUBLIC_KEY;
    public static String IN_DIR;
    public static String OUT_DIR;
    public static String BACKUP_DIR;

    private static final Logger logger = Logger.getLogger(PGPencryption.class.getName());

    static {
        loadLogger();
        loadPropertiesCache();
    }

    public static void main(String[] args) {
        File inputDirectory = new File(IN_DIR);
        File[] files = inputDirectory.listFiles();

        if (files != null) {
            for (File file : Objects.requireNonNull(files)) {
                if (file.isFile()) {
                    String inputFilePath = file.getAbsolutePath();
                    String outputFilePath = OUT_DIR + "/" + file.getName() + ".pgp";

                    try {
                        // Find public key
                        PGPPublicKey publicKey = findPublicKey(PUBLIC_KEY);

                        // Encrypt file
                        encryptFile(inputFilePath, outputFilePath, publicKey, true, true);

                        // Move the input file to backup after processing
                        moveToBackup(file.getName());
                    } catch (IOException | NoSuchProviderException | PGPException e) {
                        logger.warning("Error processing file: " + e.getMessage());
                    }
                }
            }
            logger.info("Files encrypted successfully");
        }
    }



    // ENCRYPT METHOD HERE ------------------------------------------------
    public static void encryptFile(String inputFilePath, String outputFilePath, PGPPublicKey publicKey, boolean armor, boolean withIntegrityCheck) throws IOException, PGPException {
        Security.addProvider(new BouncyCastleProvider());

        OutputStream out = new FileOutputStream(outputFilePath);

        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
        PGPCompressedDataGenerator compressedDataGen = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
        OutputStream compressedOut = compressedDataGen.open(byteOutputStream);

        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        OutputStream literalOut = literalDataGenerator.open(compressedOut, PGPLiteralData.BINARY, new File(inputFilePath));

        FileInputStream fileInputStream = new FileInputStream(inputFilePath);
        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = fileInputStream.read(buffer)) != -1) {
            literalOut.write(buffer, 0, bytesRead);
        }

        literalOut.close();
        literalDataGenerator.close();
        compressedOut.close();
        compressedDataGen.close();

        JcePGPDataEncryptorBuilder jceDataEncBuilder = new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC");
        PGPEncryptedDataGenerator encDataGenerator = new PGPEncryptedDataGenerator(jceDataEncBuilder);
        JcePublicKeyKeyEncryptionMethodGenerator jcePublicKeyEncMtdGenerator = new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider(new BouncyCastleProvider()).setSecureRandom(new SecureRandom());
        encDataGenerator.addMethod(jcePublicKeyEncMtdGenerator);

        byte[] bytes = byteOutputStream.toByteArray();
        OutputStream encryptedOut = encDataGenerator.open(out, bytes.length);
        encryptedOut.write(bytes);

        encryptedOut.close();
        out.close();
        fileInputStream.close();
    }



    // FIND PUBLIC KEY METHOD HERE ------------------------------------------------------
    private static PGPPublicKey findPublicKey(String publicKeyPath) throws IOException, NoSuchProviderException {
        try (InputStream inputStream = new FileInputStream(publicKeyPath)) {
            PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(PGPUtil.getDecoderStream(inputStream), new BcKeyFingerprintCalculator());
            Object object = pgpObjectFactory.nextObject();

            // Search for the PGP public key block
            while (object != null) {
                if (object instanceof PGPPublicKeyRing) {
                    PGPPublicKeyRing publicKeyRing = (PGPPublicKeyRing) object;
                    PGPPublicKey publicKey = publicKeyRing.getPublicKey();
                    if (publicKey.isEncryptionKey()) {
                        return publicKey;
                    }
                }
                object = pgpObjectFactory.nextObject();
            }
        } catch (IOException e) {
            System.err.println("Error reading public key: " + e.getMessage());
        }
        return null;
    }




    // CODE RUN LOCATION -----------------------------------------------------------
    public static String codeRunLocation() {
        String JARLocation = new File(PGPencryption.class.getProtectionDomain().getCodeSource().getLocation().getPath()).getParent();
//        String JARLocation = "path/of/your/config/folder";

        String PropLocation = null;
        try{
            PropLocation = JARLocation.replace("/DoNotTouch", "");
        }catch(Exception e){
            System.out.println("Failed to locate");
        }

        return PropLocation;
    }



    // LOAD PROPERTIES CACHE-------------------------------------------------------
    public static void loadPropertiesCache() {
        FileInputStream fis;
        try {
            fis = new FileInputStream(codeRunLocation() + "/config.properties");
        } catch (FileNotFoundException e) {
            logger.warning(e.toString());
            System.exit(1);
            throw new RuntimeException(e.toString());
        }
        properties = new Properties();
        try {
            properties.load(fis);
        } catch (IOException e) {
            logger.warning(e.toString());
            System.exit(1);
        }
        IN_DIR = properties.getProperty("IN_DIR") + "/";
        OUT_DIR = properties.getProperty("OUT_DIR") + "/";
        BACKUP_DIR = properties.getProperty("BACKUP_DIR") + "/";
        PUBLIC_KEY = properties.getProperty("PUBLIC_KEY");
        try {
            fis.close();
        } catch (IOException e) {
            logger.warning(e.toString());
            System.exit(1);
        }
    }


    // MOVE TO BACKUP DIRECTORY --------------------------------------------------------
    public static void moveToBackup(String fileName) throws IOException {
        Files.move(Paths.get(IN_DIR + fileName), Paths.get(BACKUP_DIR + fileName));
    }


    // LOAD LOGGER -------------------------------------------------------------------
    public static void loadLogger() {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd-MM-yyyy");
        LocalDateTime now = LocalDateTime.now();

        String logDirPath = codeRunLocation() + "/log";
        Path logDir = Paths.get(logDirPath);

        try {
            if (!Files.exists(logDir)) {
                Files.createDirectories(logDir);
            }

            String logFilePath = logDirPath + "/" + formatter.format(now) + ".log";
            FileHandler handler = new FileHandler(logFilePath, true);
            handler.setFormatter(new SimpleFormatter());
            PGPencryption.logger.addHandler(handler);
        } catch (IOException e) {
            throw new RuntimeException("Failed to create logger.", e);
        }
    }
}
