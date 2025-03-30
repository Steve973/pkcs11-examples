package com.example.pki.certs;

import com.example.pki.model.*;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.EntropySourceProvider;
import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.util.BasicEntropySourceProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.*;
import java.util.stream.Collectors;

import static com.example.pki.bcfips.ProviderUtil.BC_PROVIDER;

/**
 * Utility class for X.509 certificate operations using BouncyCastle FIPS.
 */
public class CertUtil {

    public static Collection<CertKeyPair> generateCerts(Collection<CertSpec> specs) {
        return specs.stream()
                .map(CertUtil::generateCert)
                .collect(Collectors.toList());
    }

    public static Collection<CertKeyPair> generateCerts(Collection<CertSpec> specs, KeyPair issuerKeyPair, X509Certificate issuerCert, String signatureAlgorithm) {
        return specs.stream()
                .map(spec -> generateCert(spec, issuerKeyPair, issuerCert, signatureAlgorithm))
                .collect(Collectors.toList());
    }

    /**
     * Generate a certificate based on the specification.
     */
    public static CertKeyPair generateCert(CertSpec spec) {
        return generateCert(spec, null, null, null);
    }

        /**
         * Generate a certificate based on the specification.
         */
        public static CertKeyPair generateCert(CertSpec spec, KeyPair issuerKeyPair, X509Certificate issuerCert, String issuerSignatureAlgorithm) {
        KeyPair keyPair = generateKeyPair(spec.getKeySpec());
        PrivateKey signingKey = issuerKeyPair == null ? keyPair.getPrivate() : issuerKeyPair.getPrivate();
        String signatureAlgorithm = issuerSignatureAlgorithm == null ?
                getSignatureAlgorithm(spec.getKeySpec()) :
                issuerSignatureAlgorithm;
            X500Principal issuer = issuerCert == null ?
                    new X500Principal(spec.getSubjectDn()) :
                    issuerCert.getSubjectX500Principal();
            X500Principal subject = new X500Principal(spec.getSubjectDn());
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                spec.getSerialNumber(),
                Date.from(spec.getNotBefore()),
                Date.from(spec.getNotAfter()),
                subject,
                keyPair.getPublic());
        try {
            addExtensions(certBuilder, spec, keyPair.getPublic());
            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                    .setProvider(BC_PROVIDER)
                    .build(signingKey);
            X509CertificateHolder certHolder = certBuilder.build(signer);
            X509Certificate cert = new JcaX509CertificateConverter()
                    .setProvider(BC_PROVIDER)
                    .getCertificate(certHolder);
            return new CertKeyPair(cert, keyPair.getPrivate());
        } catch (Exception e) {
            throw new RuntimeException("Error generating self-signed certificate: " + e.getMessage(), e);
        }
    }

    private static List<GeneralName> createAltNames(final CertSpec spec) {
        if (spec.getSubjectAlternativeNames() == null || spec.getSubjectAlternativeNames().isEmpty()) {
            return Collections.emptyList();
        }
        return spec.getSubjectAlternativeNames().stream()
                .map(san -> san.split(":", 2))
                .filter(parts -> {
                    if (parts.length != 2) {
                        System.err.println("Invalid SAN format. Expected 'type:value', but was: " + parts[0]);
                        return false;
                    }
                    return true;
                })
                .map(parts -> {
                    String type = parts[0].toUpperCase();
                    String value = parts[1];
                    int gnType = switch (type) {
                        case "DNS" -> GeneralName.dNSName;
                        case "IP" -> GeneralName.iPAddress;
                        case "EMAIL" -> GeneralName.rfc822Name;
                        case "URI" -> GeneralName.uniformResourceIdentifier;
                        default -> -1;
                    };
                    return gnType > -1 ? new GeneralName(gnType, value) : null;
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    private static List<KeyPurposeId> createExtendedKeyUsage(final CertSpec spec) {
        List<KeyPurposeId> purposes = new ArrayList<>();
        if (spec.getExtendedKeyUsage() != null && !spec.getExtendedKeyUsage().isEmpty()) {
            for (String usage : spec.getExtendedKeyUsage()) {
                switch (usage.toLowerCase()) {
                    case "serverauth": purposes.add(KeyPurposeId.id_kp_serverAuth); break;
                    case "clientauth": purposes.add(KeyPurposeId.id_kp_clientAuth); break;
                    case "codesigning": purposes.add(KeyPurposeId.id_kp_codeSigning); break;
                    case "emailprotection": purposes.add(KeyPurposeId.id_kp_emailProtection); break;
                    case "timestamping": purposes.add(KeyPurposeId.id_kp_timeStamping); break;
                    default: throw new IllegalArgumentException("Unsupported extended key usage: " + usage);
                }
            }
        }
        return purposes;
    }

    private static KeyUsage createKeyUsage(final CertSpec spec) {
        if (spec.getKeyUsage() == null || spec.getKeyUsage().isEmpty()) {
            return null;
        }
        return spec.getKeyUsage().stream()
                .map(KeyUsageType::fromString)
                .map(ku -> 1 << ku.getBitPosition())
                .reduce((a, b) -> a | b)
                .map(KeyUsage::new)
                .orElse(null);
    }

    /**
     * Add extensions to a certificate builder based on the specification.
     */
    static void addExtensions(X509v3CertificateBuilder certBuilder, CertSpec spec, PublicKey publicKey)
            throws IOException, NoSuchAlgorithmException {
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(publicKey));
        Optional.ofNullable(createKeyUsage(spec))
                .ifPresent(ku -> {
                    try {
                        certBuilder.addExtension(Extension.keyUsage, true, ku);
                    } catch (CertIOException e) {
                        throw new RuntimeException("Error adding key usage extension", e);
                    }
                });
        Optional.of(createExtendedKeyUsage(spec))
                .filter(eku -> !eku.isEmpty())
                .map(an -> an.toArray(new KeyPurposeId[0]))
                .map(ExtendedKeyUsage::new)
                .ifPresent(eku -> {
                    try {
                        certBuilder.addExtension(Extension.extendedKeyUsage, false, eku);
                    } catch (CertIOException e) {
                        throw new RuntimeException("Error adding extended key usage extension", e);
                    }
                });
        BasicConstraints constraints = spec.isCaCertificate() ?
                spec.getPathLenConstraint() == null ?
                        new BasicConstraints( true) :
                        new BasicConstraints(spec.getPathLenConstraint()) :
                new BasicConstraints(false);
        certBuilder.addExtension(Extension.basicConstraints, true, constraints);
        Optional.of(createAltNames(spec))
                .filter(an -> !an.isEmpty())
                .map(an -> an.toArray(new GeneralName[0]))
                .map(GeneralNames::new)
                .ifPresent(altNames -> {
                    try {
                        certBuilder.addExtension(Extension.subjectAlternativeName, false, altNames);
                    } catch (CertIOException e) {
                        throw new RuntimeException("Error adding subject alternative name extension", e);
                    }
                });
    }

    /**
     * Create a FIPS-compliant SecureRandom for key generation
     */
    static SecureRandom getFipsSecureRandom() {
        EntropySourceProvider entSource = new BasicEntropySourceProvider(new SecureRandom(), true);
        FipsDRBG.Builder drgbBldr = FipsDRBG.SHA512_HMAC.fromEntropySource(entSource)
                .setSecurityStrength(256)
                .setEntropyBitsRequired(256)
                .setPersonalizationString("CertUtilKeyGeneration".getBytes());
        return drgbBldr.build(null, true);
    }

    /**
     * Generate a key pair based on the key specification.
     */
    static KeyPair generateKeyPair(KeySpec keySpec) {
        return Optional.ofNullable(keySpec)
                .map(spec -> {
                    try {
                        SecureRandom secureRandom = getFipsSecureRandom();
                        KeyPairGenerator keyPair = KeyPairGenerator.getInstance(spec.getKeyPairAlgorithm(), BC_PROVIDER);
                        AlgorithmParameterSpec algorithmParameterSpec = spec.getAlgorithmParameterSpec();
                        keyPair.initialize(algorithmParameterSpec, secureRandom);
                        return keyPair.generateKeyPair();
                    } catch (Exception e) {
                        throw new RuntimeException("Error generating key pair", e);
                    }
                })
                .orElseThrow(() -> new IllegalArgumentException("Error generating key pair"));
    }

    /**
     * Determine the signature algorithm based on the key specification.
     */
    static String getSignatureAlgorithm(KeySpec keySpec) {
        return Optional.ofNullable(keySpec.getSignatureAlgorithm())
                .orElseThrow(() -> new IllegalArgumentException("Unsupported key type for signature algorithm"));
    }
}
