package org.example;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Iterator;
import java.util.Properties;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class PGPdecryption {

    public static Properties properties;
    public static String PRIVATE_KEY;
    public static char[] PASSPHRASE;
    public static String IN_DIR;
    public static String OUT_DIR;
    public static String BACKUP_DIR;

    private static final Logger logger = Logger.getLogger(PGPdecryption.class.getName());

    static {
        loadLogger();
        loadPropertiesCache();
    }

    public static void main(String[] args) {
        File inputDirectory = new File(IN_DIR);
        File[] files = inputDirectory.listFiles();

        if (files != null) {
            for (File file : files) {
                if (file.isFile()) {
                    String inputFilePath = file.getAbsolutePath();
                    String outputFilePath = OUT_DIR + "/" + file.getName().replace(".pgp", "");

                    try {
                        decryptFile(inputFilePath, outputFilePath, PRIVATE_KEY, PASSPHRASE);
                        moveToBackup(file.getName());
                    } catch (IOException | PGPException | NoSuchProviderException e) {
                        logger.warning("Error decrypting file: " + e.getMessage());
                    }
                }
            }
            logger.info("Files decrypted successfully");
        }logger.warning("No files found in input directory " + IN_DIR);
    }



    // DECRYPT METHOD HERE --->
    public static void decryptFile(String inputFilePath, String outputFilePath, String privateKeyPath, char[] pass) throws IOException, PGPException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());

        PGPPrivateKey privateKey = findPrivateKey(privateKeyPath, pass);
        if (privateKey == null) {
            System.err.println("Private key not found or decryption failed.");
            return;
        }

        InputStream in = new BufferedInputStream(new FileInputStream(inputFilePath));
        in = PGPUtil.getDecoderStream(in);

        try {
            PGPObjectFactory pgpF = new PGPObjectFactory(in, new BcKeyFingerprintCalculator());

            PGPEncryptedDataList enc;

            Object o = pgpF.nextObject();
            if (o instanceof PGPEncryptedDataList) {
                enc = (PGPEncryptedDataList) o;
            } else {
                enc = (PGPEncryptedDataList) pgpF.nextObject();
            }


            Iterator<PGPEncryptedData> it = enc.getEncryptedDataObjects();
            PGPPublicKeyEncryptedData pbe = null;

            while (it.hasNext()) {
                PGPEncryptedData encryptedData = it.next();
                if (encryptedData instanceof PGPPublicKeyEncryptedData) {
                    pbe = (PGPPublicKeyEncryptedData) encryptedData;
                }
            }

            if (pbe == null) {
                throw new IllegalArgumentException("Secret key for message not found.");
            }

            InputStream clear = pbe.getDataStream(new BcPublicKeyDataDecryptorFactory(privateKey));
            PGPObjectFactory plainFact = new PGPObjectFactory(clear, new BcKeyFingerprintCalculator());

            Object message = plainFact.nextObject();

            if (message instanceof PGPCompressedData) {
                PGPCompressedData cData = (PGPCompressedData) message;
                PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream(), new BcKeyFingerprintCalculator());

                message = pgpFact.nextObject();
            }

            if (message instanceof PGPLiteralData) {
                PGPLiteralData ld = (PGPLiteralData) message;

                InputStream unc = ld.getInputStream();
                OutputStream fOut = new BufferedOutputStream(new FileOutputStream(outputFilePath));

                int ch;
                while ((ch = unc.read()) >= 0) {
                    fOut.write(ch);
                }

                fOut.close();
            } else if (message instanceof PGPOnePassSignatureList) {
                throw new PGPException("Encrypted message contains a signed message - not literal data.");
            } else {
                throw new PGPException("Message is not a simple encrypted file - type unknown.");
            }

            if (pbe.isIntegrityProtected() && !pbe.verify()) {
                throw new PGPException("Message failed integrity check");
            }
        } finally {
            in.close();
        }
    }




    // FIND PRIVATE KEY METHOD HERE ---->
    private static PGPPrivateKey findPrivateKey(String privateKeyPath, char[] pass) throws IOException, PGPException {
        FileInputStream privateKeyInpStream = null;

        try {
            privateKeyInpStream = new FileInputStream(privateKeyPath);
        } catch (FileNotFoundException e) {
            System.err.println("The secret key file " + privateKeyPath + " not found");
        }

        try (ArmoredInputStream armoredInputStream = new ArmoredInputStream(privateKeyInpStream)) {
            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(armoredInputStream, new BcKeyFingerprintCalculator());

            PGPPrivateKey privateKey = null;

            outerloop:
            for (Iterator<PGPSecretKeyRing> keyRingIter = pgpSec.getKeyRings(); keyRingIter.hasNext(); ) {
                PGPSecretKeyRing keyRing = keyRingIter.next();
                for (Iterator<PGPSecretKey> keyIter = keyRing.getSecretKeys(); keyIter.hasNext(); ) {
                    PGPSecretKey key = keyIter.next();
                    try {
                        PBESecretKeyDecryptor secretKeyDecryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(pass);

                        privateKey = key.extractPrivateKey(secretKeyDecryptor);
                        if (privateKey != null) {
                            break outerloop;
                        }
                    } catch (PGPException e) {
                        // Failed to extract private key from this key, continue to the next one
                    }
                }
            }
            return privateKey;
        }
    }




// CODE RUN LOCATION ---------------------------


    public static String codeRunLocation() {
        String JARLocation = new File(PGPdecryption.class.getProtectionDomain().getCodeSource().getLocation().getPath()).getParent();
        //String JARLocation = "path/of/your/config/folder";

        String PropLocation = null;
        try{
            PropLocation = JARLocation.replace("/DoNotTouch", "");
        }catch(Exception e){
            System.out.println("Failed to locate");
        }

        return PropLocation;
    }



    // LOAD PROPERTIES CACHE ------------------------------
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
        PRIVATE_KEY = properties.getProperty("PRIVATE_KEY");
        PASSPHRASE = properties.getProperty("PASSPHRASE").toCharArray();
        try {
            fis.close();
        } catch (IOException e) {
            logger.warning(e.toString());
            System.exit(1);
        }
    }




    // MOVE TO BACKUP -------------------------------------------
    public static void moveToBackup(String fileName) throws IOException {
        Files.move(Paths.get(IN_DIR + fileName), Paths.get(BACKUP_DIR + fileName));
    }



    // LOAD LOGGER --------------------------------
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
            PGPdecryption.logger.addHandler(handler);
        } catch (IOException e) {
            throw new RuntimeException("Failed to create logger.", e);
        }
    }
}
