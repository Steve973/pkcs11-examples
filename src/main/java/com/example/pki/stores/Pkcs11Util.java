package com.example.pki.stores;

import com.example.pki.model.KeyStoreEntryInfo;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/**
 * Utility class for PKCS#11 operations using NSS database.
 */
@Slf4j
public class Pkcs11Util {

    private static final int PROCESS_TIMEOUT_SECONDS = 30;

    /**
     * Creates a temporary NSS database for PKCS#11 operations.
     *
     * @param password The password to protect the NSS DB
     * @return Path to the created NSS DB directory
     */
    public static Path createTemporaryNssDb(String password) {
        try {
            Path tempDir = Files.createTempDirectory("nssdb_");
            
            // Create a temporary password file
            Path passwordFile = Files.createTempFile(tempDir, "pwd_", ".txt");
            Files.write(passwordFile, password.getBytes());

            // Create NSS DB in SQL format with the password
            executeCommand(
                "certutil", 
                "-N", 
                "-d", "sql:" + tempDir.toAbsolutePath(), 
                "-f", passwordFile.toString());

            // Create secmod.db
            executeCommand(
                "touch",
                tempDir.toAbsolutePath() + "/secmod.db");

            // Register shutdown hook to properly clean up the directory
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try {
                    cleanupNssDb(tempDir);
                } catch (Exception e) {
                    log.error("Failed to clean up NSS database: {}", e.getMessage());
                }
            }));

            return tempDir;
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException("Failed to create NSS database", e);
        }
    }
    
    /**
     * Creates a SunPKCS11 Provider configured to use the specified NSS database.
     * 
     * @param nssDbPath Path to the NSS database directory
     * @param providerName Name to give the provider
     * @return A configured SunPKCS11 provider
     */
    public static Provider createPkcs11Provider(Path nssDbPath, String providerName) {
        try {
            Path configPath = createPkcs11ConfigFile(nssDbPath, providerName);
            return Security.getProvider("SunPKCS11")
                    .configure(configPath.toString());
        } catch (Exception e) {
            throw new RuntimeException("Failed to create PKCS#11 provider", e);
        }
    }

    /**
     * Add a keypair and certificate to the PKCS#11 keystore.
     * 
     * @param provider The SunPKCS11 provider to use
     * @param chain The certificate chain
     * @param privateKey The private key (null if adding just a certificate)
     * @param alias Alias for the entry in the keystore
     * @param password Password for the keystore
     */
    public static void addToKeyStore(
            Provider provider, 
            X509Certificate[] chain,
            PrivateKey privateKey, 
            String alias, 
            char[] password) {
        
        try {
            // Get the PKCS11 KeyStore instance from the provider
            KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
            
            // Load the keystore (initialize it)
            keyStore.load(null, password);
            
            if (privateKey != null) {
                // Store the certificate chain and private key
                keyStore.setKeyEntry(alias, privateKey, password, chain);
            } else {
                // Store just the certificate
                keyStore.setCertificateEntry(alias, chain[0]);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to add entry to PKCS#11 keystore", e);
        }
    }

    /**
     * Get info for all entries in the PKCS#11 keystore.
     *
     * @param provider The SunPKCS11 provider to use
     * @param password Password for the keystore
     * @return List of aliases in the keystore
     */
    public static List<KeyStoreEntryInfo> listKeyStoreEntries(Provider provider, char[] password) {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
            keyStore.load(null, password);
            return EntryInfoUtil.processKeyStore(keyStore, password);
        } catch (Exception e) {
            throw new RuntimeException("Failed to list PKCS#11 keystore entries", e);
        }
    }

    /**
     * Creates a PKCS#11 config file for the NSS database.
     *
     * @param nssDbPath Path to the NSS DB directory
     * @param moduleName Name for the PKCS#11 module
     * @return Path to the created config file
     */
    public static Path createPkcs11ConfigFile(Path nssDbPath, String moduleName) {
        try {
            Path configPath = Files.createTempFile(nssDbPath, "pkcs11_", ".cfg");
            
            // Basic PKCS#11 config for NSS
            String config = String.format(
                """
                name=%s
                nssLibraryDirectory=/usr/lib/x86_64-linux-gnu
                nssSecmodDirectory=%s
                nssDbMode=readWrite
                nssModule=keystore
                """,
                moduleName,
                nssDbPath.toAbsolutePath());
            
            Files.write(configPath, config.getBytes());

            return configPath;
        } catch (IOException e) {
            throw new RuntimeException("Failed to create PKCS#11 config file", e);
        }
    }
    
    /**
     * Execute a command with the given arguments.
     */
    private static void executeCommand(String... command) throws IOException, InterruptedException {
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.redirectError(ProcessBuilder.Redirect.INHERIT);
        
        Process process = processBuilder.start();
        boolean completed = process.waitFor(PROCESS_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        
        if (!completed) {
            process.destroyForcibly();
            throw new RuntimeException("Command execution timed out: " + String.join(" ", command));
        }
        
        int exitCode = process.exitValue();
        if (exitCode != 0) {
            throw new RuntimeException("Command failed with exit code " + exitCode + ": " + String.join(" ", command));
        }
    }

    /**
     * Clean up a temporary NSS DB directory.
     *
     * @param nssDbPath Path to the NSS DB directory
     */
    public static void cleanupNssDb(Path nssDbPath) {
        if (Files.exists(nssDbPath)) {
            try (Stream<Path> paths = Files.walk(nssDbPath)) {
                paths.sorted((a, b) -> -a.compareTo(b))
                .forEach(path -> {
                    try {
                        Files.delete(path);
                    } catch (IOException e) {
                        log.error("Failed to delete {}: {}", path, e.getMessage());
                    }
                });
            } catch (IOException e) {
                throw new RuntimeException("Failed to clean up NSS database", e);
            }
        }
    }
}