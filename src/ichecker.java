import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;
import static java.lang.System.exit;



/**
 * The `ichecker` class for the ichecker application.
 * This class provides functionalities to create certificates, create registries, and check file integrity.
 * The class uses the `keytool` command to generate key pairs and self-signed certificates.
 * The class has a static String variable `storePassword` to store the password for keystore encryption.
 */
public class ichecker {

    public static String storePassword;

    /**
     * Main method to execute the ichecker commands.
     *
     * @param args Command line arguments.
     * @throws Exception if an error occurs during execution.
     */
    public static void main(String[] args) throws Exception {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);



        if (args.length < 2) {
            System.out.println("Usage: ichecker <command> <args>");
            exit(1);
        }
        String command = args[0];


        try {

            System.out.print("Enter a password for keystore encryption (storepass): ");
            Scanner scanner = new Scanner(System.in);
            String storePassword2 = scanner.nextLine();
            storePassword = storePassword2;

            switch (command) {
                case "createCert":
                    String privateKeyPath = null;
                    String publicKeyCertPath = null;

                    // Parse arguments
                    for (int i = 1; i < args.length; i++) {
                        if (args[i].equals("-k")) privateKeyPath = args[++i];
                        else if (args[i].equals("-c")) publicKeyCertPath = args[++i];
                    }




                    createKeyPair(privateKeyPath, publicKeyCertPath, iv);
                    break;
                case "createReg":


                    String regFilePath = null;
                    String directoryPath = null;
                    String logFilePath = null;
                    String hashAlgorithm = null;
                    String privateKeyPath2 = null;

                    // Parse arguments
                    for (int i = 1; i < args.length; i++) {
                        switch (args[i]) {
                            case "-r":
                                regFilePath = args[++i];
                                break;
                            case "-p":
                                directoryPath = args[++i];
                                break;
                            case "-l":
                                logFilePath = args[++i];
                                break;
                            case "-h":
                                hashAlgorithm = args[++i];
                                break;
                            case "-k":
                                privateKeyPath2 = args[++i];
                                break;
                        }
                    }


                    createRegistry(regFilePath, directoryPath, logFilePath, hashAlgorithm, privateKeyPath2, iv);
                    break;
                case "check":

                    String regFilePath3 = null;
                    String directoryPath3 = null;
                    String logFilePath3 = null;
                    String hashAlgorithm3 = null;
                    String publicKeyCertPath3 = null;

                    // Parse arguments
                    for (int i = 1; i < args.length; i++) {
                        switch (args[i]) {
                            case "-r":
                                regFilePath3 = args[++i];
                                break;
                            case "-p":
                                directoryPath3 = args[++i];
                                break;
                            case "-l":
                                logFilePath3 = args[++i];
                                break;
                            case "-h":
                                hashAlgorithm3 = args[++i];
                                break;
                            case "-c":
                                publicKeyCertPath3 = args[++i];
                                break;
                        }
                    }



                    checkIntegrity(regFilePath3, directoryPath3, logFilePath3, hashAlgorithm3, publicKeyCertPath3);
                    break;
                default:
                    System.out.println("Unknown command.");
                    break;
            }

        }
        catch (Exception e) {
            System.out.println("Unknown command.");
        }

    }

    /**
     * Creates a key pair and a self-signed certificate, then encrypts the private key file. Also uses storePassword for keystore entering.
     *
     * @param privateKeyPath The path to the private key file.
     * @param certificatePath The path to the certificate file.
     * @param iv The initialization vector for encryption.
     * @throws Exception if an error occurs during key pair generation, certificate export, or file encryption.
     */
    private static void createKeyPair(String privateKeyPath, String certificatePath, byte[] iv) throws Exception {

        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter a password for key encryption: ");
        String keyPassword = scanner.nextLine();
        scanner.close();

        // Generate key pair and self-signed certificate using keytool
        String[] keytoolCmd = {
                "keytool", "-genkeypair",
                "-alias", "ichecker-cert",
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-dname", "CN=ichecker-cert", // Subject for the certificate
                "-validity", "365",
                "-keystore", privateKeyPath,
                "-storepass", storePassword,
                "-keypass", storePassword,
                "-storetype", "PKCS12" // Store type for portability
        };

        executeCommand(keytoolCmd);

        // Export certificate from keystore
        String[] exportCertCmd = {
                "keytool", "-exportcert",
                "-alias", "ichecker-cert",
                "-keystore", privateKeyPath,
                "-storepass", storePassword,
                "-file", certificatePath
        };

        executeCommand(exportCertCmd);

        System.out.println("Key pair and certificate created: " + privateKeyPath + ", " + certificatePath);

        try {
            BufferedWriter writer = new BufferedWriter(new FileWriter(privateKeyPath, true));
            writer.newLine();
            writer.write("PRIVATEKEY");
            writer.close();
        } catch (IOException e) {
            System.out.println("An error occurred during file operation: " + e.getMessage());
        }

        // Encrypt the private key file
        encryptPrivateKeyFile(privateKeyPath, keyPassword, iv);
    }


    /**
     * Executes a command in the system shell.
     *
     * @param command The command to execute.
     * @throws Exception if an error occurs during command execution.
     */
    private static void executeCommand(String[] command) throws Exception {
        Process process = new ProcessBuilder(command).start();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
             BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {

            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            while ((line = errorReader.readLine()) != null) {
                System.err.println(line);
            }
        }
        process.waitFor();
    }

    /**
     * Encrypts data using AES encryption.
     *
     * @param data The data to encrypt.
     * @param password The password to use for encryption.
     * @param iv The initialization vector.
     * @return The encrypted data.
     * @throws Exception if an error occurs during encryption.
     */
public static byte[] aesEncrypt(byte[] data, String password, byte[] iv) throws Exception {
    byte[] key = md5Hash(password);

    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
    byte[] encryptedData = cipher.doFinal(data);

    byte[] result = new byte[iv.length + encryptedData.length];
    System.arraycopy(iv, 0, result, 0, iv.length);
    System.arraycopy(encryptedData, 0, result, iv.length, encryptedData.length);

    return result;
}

 /**
     * Decrypts data using AES decryption.
     *
     * @param data The data to decrypt.
     * @param password The password to use for decryption.
     * @return The decrypted data.
     * @throws Exception if an error occurs during decryption.
     */
    public static byte[] aesDecrypt(byte[] data, String password) throws Exception {
        byte[] key = md5Hash(password);

        byte[] iv = new byte[16];
        System.arraycopy(data, 0, iv, 0, iv.length);

        byte[] encryptedData = new byte[data.length - iv.length];
        System.arraycopy(data, iv.length, encryptedData, 0, encryptedData.length);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));

        return cipher.doFinal(encryptedData);
    }

    /**
     * Generates an MD5 hash of a password.
     *
     * @param password The password to hash.
     * @return The MD5 hash of the password.
     * @throws NoSuchAlgorithmException if the MD5 algorithm is not available.
     */
    public static byte[] md5Hash(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Encrypts a private key file using AES encryption.
     *
     * @param privateKeyPath The path to the private key file.
     * @param key The password to use for encryption.
     * @param iv The initialization vector.
     * @throws Exception if an error occurs during encryption.
     */
    private static void encryptPrivateKeyFile(String privateKeyPath, String key, byte[] iv) throws Exception {
        File privateKeyFile = new File(privateKeyPath);
        File encryptedPrivateKeyFile = new File(privateKeyFile.getParent(), "encrypted_" + privateKeyFile.getName());


        byte[] privateKeyData = new byte[(int) privateKeyFile.length()];

        try (FileInputStream fis = new FileInputStream(privateKeyFile)) {
            fis.read(privateKeyData);
        }

        byte[] encryptedData = aesEncrypt(privateKeyData, key, iv);

        try (FileOutputStream fos = new FileOutputStream(encryptedPrivateKeyFile)) {
            fos.write(encryptedData);
        }

    }


    /**
     * Verifies the signature of a registry file using a certificate.
     *
     * @param registryPath The path to the registry file.
     * @param certificatePath The path to the certificate file.
     * @return true if the signature is valid, false otherwise.
     * @throws Exception if an error occurs during verification.
     */
    public static boolean verifySignature(String registryPath, String certificatePath) throws Exception {
        List<String> lines = Files.readAllLines(Paths.get(registryPath));
        String content = String.join("\n", lines.subList(0, lines.size() - 1));
        byte[] signature = Base64.getDecoder().decode(lines.get(lines.size() - 1).split("#signature#")[1]);

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert;
        try (FileInputStream fis = new FileInputStream(certificatePath)) {
            cert = (X509Certificate) certFactory.generateCertificate(fis);
        }
        PublicKey publicKey = cert.getPublicKey();

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(content.getBytes());

        try {
            return sig.verify(signature);
        } catch (SignatureException e) {
            return false;
        }
    }

    /**
     * Computes the hash of a file using the specified algorithm.
     *
     * @param filePath The path to the file.
     * @param algorithm The hash algorithm to use (MD5 or SHA-256).
     * @return The hash of the file.
     * @throws Exception if an error occurs during hashing.
     */
    public static String hashFile(String filePath, String algorithm) throws Exception {
        MessageDigest hasher = MessageDigest.getInstance(algorithm.equals("MD5") ? "MD5" : "SHA-256");
        try (InputStream fis = Files.newInputStream(Paths.get(filePath))) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                hasher.update(buffer, 0, bytesRead);
            }
        }
        return Base64.getEncoder().encodeToString(hasher.digest());
    }

    /**
     * Logs a message to a log file with a timestamp.
     *
     * @param logFile The path to the log file.
     * @param message The message to log.
     * @throws IOException if an error occurs during file operation.
     */
    public static void logMessage(String logFile, String message) throws IOException {
        String timestamp = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss").format(new Date());
        try (BufferedWriter log = new BufferedWriter(new FileWriter(logFile, true))) {
            log.write(timestamp + ": " + message + "\n");
        }
    }

    /**
     * Retrieves the private key from a keystore. Also uses storePassword for keystore entering.
     *
     * @param privateKeyPath The path to the private key file.
     * @return The private key.
     * @throws Exception if an error occurs during key retrieval.
     */
    private static PrivateKey getPrivateKey(String privateKeyPath) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(privateKeyPath)) {
            keyStore.load(fis,  storePassword.toCharArray());
        }
        return (PrivateKey) keyStore.getKey("ichecker-cert", storePassword.toCharArray());
    }

    /**
     * Creates a registry file with file hashes and a digital signature.
     *
     * @param registryPath The path to the registry file.
     * @param directoryPath The path to the directory to scan.
     * @param logPath The path to the log file.
     * @param hashAlgorithm The hash algorithm to use (MD5 or SHA-256).
     * @param privateKeyPath The path to the private key file.
     * @param iv The initialization vector for encryption.
     * @throws Exception if an error occurs during registry creation.
     */
    public static void createRegistry(String registryPath, String directoryPath, String logPath,  String hashAlgorithm, String privateKeyPath, byte[] iv) throws Exception {
        // Generate registry file
        String dirpath= directoryPath;

//        System.out.println(privateKeyPath);
        System.out.print("Enter a password to decrypt the private key: ");
        Scanner scanner = new Scanner(System.in);
        String password2 = scanner.nextLine();
        if (password2.isEmpty()||password2.length()% 16 !=0) {
            System.out.println("Password incorrect");
            exit(1);
        }


        scanner.close();


        File privateKeyFile = new File(privateKeyPath);
        File encryptedPrivateKeyFile = new File(privateKeyFile.getParent(), "encrypted_" + privateKeyFile.getName());

        byte[] decryptedPrivateKey = null;
        try {
             decryptedPrivateKey = aesDecrypt(new FileInputStream(encryptedPrivateKeyFile).readAllBytes(), password2);
        }
        catch (Exception e) {
            System.out.println("Password incorrect");
            exit(1);
        }

        try (FileOutputStream fos = new FileOutputStream(privateKeyPath + ".dec")) {
            fos.write(decryptedPrivateKey);
        }
        catch (IOException e) {

            System.out.println("An error occurred during file operation: " + e.getMessage());
        }

        String DecryptedPrivateKeyPath = privateKeyPath + ".dec";
        try {
            String context = new String(Files.readAllBytes(Paths.get(DecryptedPrivateKeyPath)));



            String[] lines = context.split(System.lineSeparator());
            String lastLine = lines[lines.length - 1];
            if (lastLine.equals("PRIVATEKEY")) {

                Map<String, String> registry = new HashMap<>();
                Files.walk(Paths.get(dirpath))
                        .filter(Files::isRegularFile)
                        .forEach(filePath -> {
                            try {
                                String hash = hashFile(filePath.toString(), hashAlgorithm);
                                registry.put(filePath.toString(), hash);
                                logMessage(logPath, filePath.toString() + " is added to registry.");
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        });

                // Prepare the content for the registry file
                String registryContent = registry.entrySet()
                        .stream()
                        .map(entry -> entry.getKey() + " " + entry.getValue())
                        .collect(Collectors.joining("\n"));

                // Sign the registry content
                Signature signature = Signature.getInstance("SHA256withRSA");
                PrivateKey privateKey = getPrivateKey(DecryptedPrivateKeyPath);
                signature.initSign(privateKey);
                signature.update(registryContent.getBytes());
                byte[] signedData = signature.sign();

                // Write the registry file with the signature
                try (BufferedWriter writer = Files.newBufferedWriter(Paths.get(registryPath), StandardOpenOption.CREATE)) {
                    writer.write(registryContent + "\n#signature#" + Base64.getEncoder().encodeToString(signedData));
                }

                logMessage(logPath, registry.size() + " files added, registry created at " + registryPath + ".");

            } else {
                System.out.println("The PRIVATEKEY expression was not found in the file.");
                exit(1);
                ichecker.createRegistry(registryPath, directoryPath, logPath, hashAlgorithm, privateKeyPath, iv);

            }

        } catch (IOException e) {
            System.out.println("An error occurred during file operation: " + e.getMessage());
        }

    }

    /**
     * Checks the integrity of files in a directory against a registry file.
     *
     * @param registryPath The path to the registry file.
     * @param directory The path to the directory to check.
     * @param logFile The path to the log file.
     * @param algorithm The hash algorithm to use (MD5 or SHA-256).
     * @param certificatePath The path to the certificate file.
     * @throws Exception if an error occurs during integrity check.
     */
    public static void checkIntegrity(String registryPath, String directory, String logFile, String algorithm, String certificatePath) throws Exception {
        if (!verifySignature(registryPath, certificatePath)) {
            logMessage(logFile, "Registry file verification failed!");
            System.out.println("Registry verification failed.");
            System.exit(1);
        }

        List<String> lines = Files.readAllLines(Paths.get(registryPath));
        Map<String, String> registry = new HashMap<>();
        for (String line : lines.subList(0, lines.size() - 1)) {
            String[] parts = line.split(" ");
            registry.put(parts[0], parts[1]);
        }

        Map<String, String> currentFiles = new HashMap<>();
        Files.walk(Paths.get(directory)).filter(Files::isRegularFile).forEach(filePath -> {
            try {
                currentFiles.put(filePath.toString(), hashFile(filePath.toString(), algorithm));
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        List<String> changes = new ArrayList<>();
        for (Map.Entry<String, String> entry : registry.entrySet()) {
            String path = entry.getKey();
            String hashValue = entry.getValue();
            if (!currentFiles.containsKey(path)) {
                changes.add(path + " deleted");
            } else if (!currentFiles.get(path).equals(hashValue)) {
                changes.add(path + " altered");
            }
        }
        for (String path : currentFiles.keySet()) {
            if (!registry.containsKey(path)) {
                changes.add(path + " created");
            }
        }

        if (!changes.isEmpty()) {
            for (String change : changes) {
                logMessage(logFile, change);
            }
            System.out.println("Changes detected, logged.");
        } else {
            logMessage(logFile, "No changes detected.");
        }
    }

}