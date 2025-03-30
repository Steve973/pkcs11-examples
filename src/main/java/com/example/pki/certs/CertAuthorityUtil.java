package com.example.pki.certs;

import com.example.pki.model.*;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Set;

import static com.example.pki.bcfips.ProviderUtil.BC_PROVIDER;

@Slf4j
public class CertAuthorityUtil {

    /**
     * Creates a CA certificate chain with Root and Intermediate CAs.
     *
     * @return A map containing the key pairs and certificates for both CAs
     */
    public static CertificateAuthorityMaterial createCaCertificateChain() {
        try {
            // Step 1: Generate Root CA
            CertSpec rootCaSpec = createRootCaSpec();
            KeyPair rootKeyPair = CertUtil.generateKeyPair(rootCaSpec.getKeySpec());
            String rootSigAlgName = rootCaSpec.getKeySpec().getSignatureAlgorithm();
            CertKeyPair rootCaCertKeyPair = CertUtil.generateCert(rootCaSpec, rootKeyPair, null, null);
            X509Certificate rootCaCert = rootCaCertKeyPair.certificate();

            // Step 2: Generate Intermediate CA signed by Root CA
            CertSpec intermediateCaSpec = createIntermediateCaSpec();
            KeyPair intermediateKeyPair = CertUtil.generateKeyPair(intermediateCaSpec.getKeySpec());
            String intermediateSigAlgName = intermediateCaSpec.getKeySpec().getSignatureAlgorithm();
            X509Certificate intermediateCert = generateSignedCert(
                    intermediateCaSpec, intermediateKeyPair.getPublic(), rootCaCert, rootKeyPair.getPrivate());

            // Create certificate chain
            X509Certificate[] caChain = new X509Certificate[] { intermediateCert, rootCaCert };

            return new CertificateAuthorityMaterial(rootKeyPair, rootSigAlgName, rootCaCert, intermediateKeyPair,
                    intermediateSigAlgName, intermediateCert, caChain);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create CA certificate chain", e);
        }
    }

    /**
     * Creates a specification for a Root CA certificate.
     */
    private static CertSpec createRootCaSpec() {
        return CertSpec.builder()
                .subjectDn("CN=Root CA, O=Example Organization, C=US")
                .serialNumber(generateRandomSerial())
                .notBefore(Instant.now())
                .notAfter(Instant.now().plus(10 * 365, ChronoUnit.DAYS)) // 10 years validity
                .keyUsage(Set.of("keyCertSign", "crlSign", "digitalSignature"))
                .caCertificate(true)
                .pathLenConstraint(1) // Can sign intermediate CAs
                .keySpec(RsaKeySpec.builder()
                        .keyLabel("root-ca-key")
                        .build())
                .build();
    }

    /**
     * Creates a specification for an Intermediate CA certificate.
     */
    private static CertSpec createIntermediateCaSpec() {
        return CertSpec.builder()
                .subjectDn("CN=Intermediate CA, O=Example Organization, C=US")
                .serialNumber(generateRandomSerial())
                .notBefore(Instant.now())
                .notAfter(Instant.now().plus(5 * 365, ChronoUnit.DAYS)) // 5 years validity
                .keyUsage(Set.of("keyCertSign", "crlSign", "digitalSignature"))
                .caCertificate(true)
                .pathLenConstraint(1)
                .keySpec(EcKeySpec.builder()
                        .keyLabel("intermediate-ca-key")
                        .build())
                .build();
    }

    /**
     * Generates a random serial number for a certificate.
     */
    private static BigInteger generateRandomSerial() {
        SecureRandom random = CertUtil.getFipsSecureRandom();
        return new BigInteger(160, random);
    }

    /**
     * Generate a certificate signed by an issuer certificate.
     *
     * @param spec Subject certificate specification
     * @param publicKey Subject's public key
     * @param issuerCert Issuer's certificate
     * @param issuerPrivateKey Issuer's private key
     * @return X509Certificate signed by the issuer
     */
    private static X509Certificate generateSignedCert(CertSpec spec, PublicKey publicKey,
                                                     X509Certificate issuerCert, PrivateKey issuerPrivateKey) {
        try {
            // Create a modified spec with issuer as the signer
            CertSpec signedSpec = CertSpec.builder()
                    .subjectDn(spec.getSubjectDn())
                    .serialNumber(spec.getSerialNumber())
                    .notBefore(spec.getNotBefore())
                    .notAfter(spec.getNotAfter())
                    .keyUsage(spec.getKeyUsage())
                    .extendedKeyUsage(spec.getExtendedKeyUsage())
                    .subjectAlternativeNames(spec.getSubjectAlternativeNames())
                    .caCertificate(spec.isCaCertificate())
                    .pathLenConstraint(spec.getPathLenConstraint())
                    .keySpec(spec.getKeySpec())
                    .build();

            X500Principal subject = new X500Principal(signedSpec.getSubjectDn());
            X500Principal issuer = issuerCert.getSubjectX500Principal();

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    issuer,
                    signedSpec.getSerialNumber(),
                    Date.from(signedSpec.getNotBefore()),
                    Date.from(signedSpec.getNotAfter()),
                    subject,
                    publicKey);

            // Add extensions
            CertUtil.addExtensions(certBuilder, signedSpec, publicKey);

            // Add authority key identifier extension
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            certBuilder.addExtension(
                    Extension.authorityKeyIdentifier,
                    false,
                    extUtils.createAuthorityKeyIdentifier(issuerCert));

            // Sign the certificate with the issuer's private key
            ContentSigner signer = new JcaContentSignerBuilder(issuerCert.getSigAlgName())
                    .setProvider(BC_PROVIDER)
                    .build(issuerPrivateKey);

            X509CertificateHolder certHolder = certBuilder.build(signer);

            // Convert to X509Certificate
            return new JcaX509CertificateConverter()
                    .setProvider(BC_PROVIDER)
                    .getCertificate(certHolder);

        } catch (Exception e) {
            throw new RuntimeException("Error generating signed certificate", e);
        }
    }
}
