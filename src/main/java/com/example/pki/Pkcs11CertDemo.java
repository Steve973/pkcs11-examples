package com.example.pki;

import com.example.pki.certs.CertAuthorityUtil;
import com.example.pki.certs.CertUtil;
import com.example.pki.model.*;
import com.example.pki.stores.Pkcs11Util;
import com.example.pki.stores.Pkcs12Util;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
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
            KeyStore pfxStore = createPfxKeyStore(certKeyPairs, caMaterial);
            displayPfxStoreContents(pfxStore);
            storeCertificatesInDb(certKeyPairs, new X509Certificate[]{caMaterial.intermediateCertificate(), caMaterial.rootCertificate()}, pkcs11Provider);
            displayDbContents(pkcs11Provider);
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
     * Create a PFX keystore with certificates.
     */
    private KeyStore createPfxKeyStore(List<CertKeyPair> certKeyPairs, CertificateAuthorityMaterial caMaterial) throws Exception {
        List<PfxKeyEntry> keyEntries = new ArrayList<>();
        List<PfxCertEntry> certEntries = new ArrayList<>();

        // Add Root CA as a trusted certificate
        certEntries.add(new PfxCertEntry(
                caMaterial.rootCertificate(),
                new HashMap<>() {{
                    put(
                            PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                            new DERBMPString("root-ca-trust"));
                    put(
                            PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                            new DEROctetString(caMaterial.rootCertificate().getPublicKey().getEncoded()));
                }},
                true)); // Mark as trusted

        // Add Intermediate CA as a trusted certificate
        certEntries.add(new PfxCertEntry(
                caMaterial.intermediateCertificate(),
                new HashMap<>() {{
                    put(
                            PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                            new DERBMPString("intermediate-ca-trust"));
                    put(
                            PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                            new DEROctetString(caMaterial.intermediateCertificate().getPublicKey().getEncoded()));
                }},
                true)); // Mark as trusted

        // Server cert with SSL trust
        keyEntries.add(new PfxKeyEntry(
                certKeyPairs.get(0).privateKey(),
                new HashMap<>() {{
                    put(
                            PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                            new DERBMPString("server-key"));
                    put(
                            PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                            new DEROctetString(certKeyPairs.get(0).certificate().getPublicKey().getEncoded()));
                }}));
        certEntries.add(new PfxCertEntry(
                certKeyPairs.get(0).certificate(),
                new HashMap<>() {{
                    put(
                            PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                            new DERBMPString("server-key-trusted"));
                    put(
                            PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                            new DEROctetString(certKeyPairs.get(0).certificate().getPublicKey().getEncoded()));
                }},
                true));

        // Client cert with client authentication trust
        keyEntries.add(new PfxKeyEntry(
                certKeyPairs.get(1).privateKey(),
                new HashMap<>() {{
                    put(
                            PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                            new DERBMPString("server-cert"));
                    put(
                            PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                            new DEROctetString(certKeyPairs.get(1).certificate().getPublicKey().getEncoded()));
                }}));
        certEntries.add(new PfxCertEntry(
                certKeyPairs.get(1).certificate(),
                new HashMap<>() {{
                    put(
                            PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                            new DERBMPString("server-cert-trusted"));
                    put(
                            PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                            new DEROctetString(certKeyPairs.get(1).certificate().getPublicKey().getEncoded()));
                }},
                true));

        // Code signing cert
        keyEntries.add(new PfxKeyEntry(
                certKeyPairs.get(2).privateKey(),
                new HashMap<>() {{
                    put(
                            PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                            new DERBMPString("code-signing"));
                    put(
                            PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                            new DEROctetString(certKeyPairs.get(2).certificate().getPublicKey().getEncoded()));
                }}));
        certEntries.add(new PfxCertEntry(
                certKeyPairs.get(2).certificate(),
                new HashMap<>() {{
                    put(
                            PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                            new DERBMPString("code-signing-trusted"));
                    put(
                            PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                            new DEROctetString(certKeyPairs.get(2).certificate().getPublicKey().getEncoded()));
                }},
                true));

        // CA cert with full trust
        keyEntries.add(new PfxKeyEntry(
                certKeyPairs.get(3).privateKey(),
                new HashMap<>() {{
                    put(
                            PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                            new DERBMPString("server-ca"));
                    put(
                            PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                            new DEROctetString(certKeyPairs.get(3).certificate().getPublicKey().getEncoded()));
                }}));
        certEntries.add(new PfxCertEntry(
                certKeyPairs.get(3).certificate(),
                new HashMap<>() {{
                    put(
                            PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                            new DERBMPString("server-ca-trusted"));
                    put(
                            PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                            new DEROctetString(certKeyPairs.get(3).certificate().getPublicKey().getEncoded()));
                }},
                true));

        // Create the PFX data
        byte[] pfxData = Pkcs12Util.createPfxStore(
                NSS_DB_PASSWORD.toCharArray(),
                keyEntries,
                certEntries);

        // Load the PFX data into a KeyStore object
        KeyStore keyStore = KeyStore.getInstance("PKCS12", BC_PROVIDER);
        InputStream pfxStream = new ByteArrayInputStream(pfxData);
        keyStore.load(pfxStream, NSS_DB_PASSWORD.toCharArray());

        return keyStore;
    }


    private void displayStoreContents(String name, List<KeyStoreEntryInfo> info) {
        String entryInfo = info.stream()
                .sorted(Comparator.comparing(KeyStoreEntryInfo::getAlias))
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