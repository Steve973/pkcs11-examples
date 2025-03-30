package com.example.pki;

import com.example.pki.certs.CertAuthorityUtil;
import com.example.pki.certs.CertUtil;
import com.example.pki.model.*;
import com.example.pki.stores.Pkcs11Util;
import com.example.pki.stores.Pkcs12Util;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

import static com.example.pki.bcfips.ProviderUtil.BC_PROVIDER;

/**
 * Demonstrates certificate creation and PKCS#11 operations with NSS database.
 */
@Slf4j
public class Pkcs11CertDemo {
    
    private static final String NSS_DB_PASSWORD = "changeit";

    private Path nssDbPath;

    /**
     * Entry point for the demo.
     */
    public static void main(String[] args) {
        Pkcs11CertDemo demo = new Pkcs11CertDemo();
        demo.run();
    }
    
    /**
     * Run the demonstration.
     */
    public void run() {
        try {
            initializeNssDb();
            Provider pkcs11Provider = Pkcs11Util.createPkcs11Provider(nssDbPath, "TestProvider");
            CertificateAuthorityMaterial caMaterial = CertAuthorityUtil.createCaCertificateChain();
            List<CertKeyPair> certKeyPairs = new ArrayList<>(generateCertificates(caMaterial));
            storeCertificatesInDb(certKeyPairs, new X509Certificate[]{caMaterial.intermediateCertificate(), caMaterial.rootCertificate()}, pkcs11Provider);
            displayDbContents(pkcs11Provider);
            KeyStore pfxStore = createPfxKeyStore(certKeyPairs, caMaterial);
            displayPfxStoreContents(pfxStore);
        } catch (Exception e) {
            log.error("Error in PKCS#11 demo", e);
        }
    }
    
    /**
     * Initialize a temporary NSS database.
     */
    private void initializeNssDb() {
        nssDbPath = Pkcs11Util.createTemporaryNssDb(NSS_DB_PASSWORD);
    }
    
    /**
     * Generate a set of different certificate types.
     */
    private Collection<CertKeyPair> generateCertificates(CertificateAuthorityMaterial caMaterial) {
        List<CertSpec> specs = Arrays.asList(
            createRsaServerCertSpec(),
            createEcClientCertSpec(),
            createDsaCodeSigningCertSpec(),
            createCaCertSpec());
        
        return CertUtil.generateCerts(specs, caMaterial.intermediateKeyPair(), caMaterial.intermediateCertificate(), caMaterial.intermediateSigAlgName());
    }
    
    /**
     * Store certificates in the NSS database with appropriate trust settings.
     */
    private void storeCertificatesInDb(List<CertKeyPair> certKeyPairs, X509Certificate[] chain, Provider provider) {
        List<X509Certificate> chainCerts = new ArrayList<>();

        // Add Root CA as a trusted certificate
        chainCerts.add(chain[1]);
        Pkcs11Util.addToKeyStore(
                provider,
                chainCerts.toArray(new X509Certificate[0]),
                null,
                "ca-root-trust",
                NSS_DB_PASSWORD.toCharArray());

        // Add Intermediate CA as a trusted certificate
        chainCerts.add(0, chain[0]);
        Pkcs11Util.addToKeyStore(
                provider,
                chainCerts.toArray(new X509Certificate[0]),
                null,
                "ca-intermediate-trust",
                NSS_DB_PASSWORD.toCharArray());

        // Server cert with SSL trust
        chainCerts.add(0, certKeyPairs.get(0).certificate());
        Pkcs11Util.addToKeyStore(
                provider,
                chainCerts.toArray(new X509Certificate[0]),
                certKeyPairs.get(0).privateKey(),
                "server-cert",
                NSS_DB_PASSWORD.toCharArray());

        // Client cert with client authentication trust
        chainCerts.set(0, certKeyPairs.get(1).certificate());
        Pkcs11Util.addToKeyStore(
                provider,
                chainCerts.toArray(new X509Certificate[0]),
                certKeyPairs.get(1).privateKey(),
                "client-cert",
                NSS_DB_PASSWORD.toCharArray());

        // Code signing cert
        chainCerts.set(0, certKeyPairs.get(2).certificate());
        Pkcs11Util.addToKeyStore(
                provider,
                chainCerts.toArray(new X509Certificate[0]),
                certKeyPairs.get(2).privateKey(),
                "code-signing-cert",
                NSS_DB_PASSWORD.toCharArray());

        // CA cert with full trust
        chainCerts.set(0, certKeyPairs.get(3).certificate());
        Pkcs11Util.addToKeyStore(
                provider,
                chainCerts.toArray(new X509Certificate[0]),
                certKeyPairs.get(3).privateKey(),
                "ca-other-cert",
                NSS_DB_PASSWORD.toCharArray());
    }

    /**
     * Creates a PFX keystore with private keys and their certificate chains
     */
    private KeyStore createPfxKeyStore(List<CertKeyPair> certKeyPairs, CertificateAuthorityMaterial caMaterial) throws Exception {
        // Add server certificate with its private key
        CertKeyPair serverCert = certKeyPairs.get(0);
        List<PfxKeyEntry> keyEntries = List.of(
                new PfxKeyEntry(
                        serverCert.privateKey(),
                        new HashMap<>() {{
                            put(
                                    PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                                    new DERBMPString("server-key"));
                            put(
                                    PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                                    new DEROctetString(serverCert.certificate().getPublicKey().getEncoded()));
                        }}));

        // Prepare certificate entries for the CA certificates
        List<PfxCertEntry> certEntries = List.of(
                new PfxCertEntry(
                        serverCert.certificate(),
                        new HashMap<>() {{
                            put(
                                    PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                                    new DERBMPString("server-cert"));
                            put(
                                    PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                                    new DEROctetString(serverCert.certificate().getPublicKey().getEncoded()));
                        }},
                        false),
                new PfxCertEntry(
                        caMaterial.intermediateCertificate(),
                        new HashMap<>() {{
                            put(
                                    PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                                    new DERBMPString("Intermediate CA 2"));
                            put(
                                    PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                                    new DEROctetString(caMaterial.intermediateCertificate().getPublicKey().getEncoded()));
                        }},
                        true),
                new PfxCertEntry(
                        caMaterial.rootCertificate(),
                        new HashMap<>() {{
                            put(
                                    PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                                    new DERBMPString("Root CA"));
                            put(
                                    PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                                    new DEROctetString(caMaterial.rootCertificate().getPublicKey().getEncoded()));
                        }},
                        true));

        byte[] pfxData = Pkcs12Util.createPfxStore(NSS_DB_PASSWORD.toCharArray(), keyEntries, certEntries);

        KeyStore keyStore = KeyStore.getInstance("PKCS12", BC_PROVIDER);
        try (InputStream ksis = new ByteArrayInputStream(pfxData)) {
            keyStore.load(ksis, NSS_DB_PASSWORD.toCharArray());
        }
        return keyStore;
    }

    private void displayStoreContents(String name, List<KeyStoreEntryInfo> info) {
        String entryInfo = info.stream()
                .map(KeyStoreEntryInfo::toString)
                .collect(Collectors.joining("\n"));
        String details = """
                
                
                ====================== %s Contents ======================
                %s"""
                .formatted(name, entryInfo);
        log.info(details);
    }

    /**
     * Display contents of the NSS database.
     */
    private void displayDbContents(Provider provider) {
        displayStoreContents("NSS Database", Pkcs11Util.listKeyStoreEntries(provider, NSS_DB_PASSWORD.toCharArray()));
    }

    /**
     * Display contents of the NSS database.
     */
    private void displayPfxStoreContents(KeyStore keyStore) {
        List<KeyStoreEntryInfo> info = Pkcs12Util.listKeyStoreEntries(keyStore, NSS_DB_PASSWORD.toCharArray());
        displayStoreContents("PFX Store", info);
    }

    /**
     * Create an RSA certificate spec for TLS server authentication.
     */
    private CertSpec createRsaServerCertSpec() {
        return CertSpec.builder()
                .subjectDn("CN=server.example.com, O=Example Inc, L=San Francisco, ST=California, C=US")
                .serialNumber(generateRandomSerial())
                .notBefore(Instant.now())
                .notAfter(Instant.now().plus(365, ChronoUnit.DAYS))
                .keyUsage(Set.of("digitalSignature", "keyEncipherment"))
                .extendedKeyUsage(Set.of("serverAuth"))
                .subjectAlternativeNames(Arrays.asList(
                        "DNS:server.example.com",
                        "DNS:*.example.com",
                        "IP:192.168.1.1"
                ))
                .keySpec(RsaKeySpec.builder()
                        .keyLabel("server-key")
                        .build())
                .build();
    }

    /**
     * Create an EC certificate spec for TLS client authentication.
     */
    private CertSpec createEcClientCertSpec() {
        return CertSpec.builder()
                .subjectDn("CN=client@example.com, O=Example Inc, L=San Francisco, ST=California, C=US")
                .serialNumber(generateRandomSerial())
                .notBefore(Instant.now())
                .notAfter(Instant.now().plus(365, ChronoUnit.DAYS))
                .keyUsage(Set.of("digitalSignature"))
                .extendedKeyUsage(Set.of("clientAuth", "emailProtection"))
                .subjectAlternativeNames(List.of("EMAIL:client@example.com"))
                .keySpec(EcKeySpec.builder()
                        .keyLabel("client-key")
                        .build())
                .build();
    }

    /**
     * Create a DSA certificate spec for code signing.
     */
    private CertSpec createDsaCodeSigningCertSpec() {
        return CertSpec.builder()
                .subjectDn("CN=Code Signing Cert, O=Example Inc, L=San Francisco, ST=California, C=US")
                .serialNumber(generateRandomSerial())
                .notBefore(Instant.now())
                .notAfter(Instant.now().plus(365, ChronoUnit.DAYS))
                .keyUsage(Set.of("digitalSignature"))
                .extendedKeyUsage(Set.of("codeSigning"))
                .keySpec(DsaKeySpec.builder()
                        .keyLabel("code-signing-key")
                        .build())
                .build();
    }

    /**
     * Create a CA certificate spec.
     */
    private CertSpec createCaCertSpec() {
        return CertSpec.builder()
                .subjectDn("CN=Example CA, O=Example Inc, L=San Francisco, ST=California, C=US")
                .serialNumber(generateRandomSerial())
                .notBefore(Instant.now())
                .notAfter(Instant.now().plus(3650, ChronoUnit.DAYS)) // 10 years
                .keyUsage(Set.of("keyCertSign", "crlSign", "digitalSignature"))
                .caCertificate(true)
                .pathLenConstraint(0) // No intermediate CAs allowed
                .keySpec(RsaKeySpec.builder()
                        .keyLabel("ca-key")
                        .build())
                .build();
    }

    /**
     * Generate a random certificate serial number.
     */
    private BigInteger generateRandomSerial() {
        return new BigInteger(64, new Random());
    }
}