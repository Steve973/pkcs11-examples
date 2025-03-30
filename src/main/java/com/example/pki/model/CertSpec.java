package com.example.pki.model;

import lombok.Builder;
import lombok.Data;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.HashSet;

/**
 * Specification for X.509 certificate generation.
 */
@Data
@Builder
public class CertSpec {

    /**
     * Subject Distinguished Name (DN) in X.500 format
     * e.g., "CN=Example, O=Organization, C=US"
     */
    private String subjectDn;
    
    /**
     * Certificate validity start time
     */
    @Builder.Default
    private Instant notBefore = Instant.now();
    
    /**
     * Certificate validity end time
     */
    @Builder.Default
    private Instant notAfter = Instant.now().plus(Duration.ofDays(365));
    
    /**
     * Certificate serial number
     */
    @Builder.Default
    private BigInteger serialNumber = generateSerialNumber();

    /**
     * Allows the serial number field to have a default value
     * that throws an exception.
     *
     * @return a randomly generated BigInteger to serve as the certificate serial number.
     */
    private static BigInteger generateSerialNumber() {
        try {
            return new BigInteger(64, SecureRandom.getInstanceStrong());
        } catch (NoSuchAlgorithmException e) {
            // Fallback to regular SecureRandom
            return new BigInteger(64, new SecureRandom());
        }
    }

    /**
     * Key usage flags
     * Possible values: digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment,
     * keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly
     */
    @Builder.Default
    private Set<String> keyUsage = new HashSet<>();
    
    /**
     * Extended key usage options
     * Possible values: serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, etc.
     */
    @Builder.Default
    private Set<String> extendedKeyUsage = new HashSet<>();
    
    /**
     * Subject Alternative Names (SANs)
     * Format: type:value (e.g., "DNS:example.com", "IP:192.168.1.1", "EMAIL:user@example.com")
     */
    @Builder.Default
    private List<String> subjectAlternativeNames = new ArrayList<>();
    
    /**
     * Key specification (can be RsaKeySpec, EcKeySpec, or DsaKeySpec)
     */
    private KeySpec keySpec;
    
    /**
     * Whether the certificate is a CA certificate
     */
    @Builder.Default
    private boolean caCertificate = false;
    
    /**
     * Basic constraints path length (for CA certificates)
     * null means no path length constraint
     */
    @Builder.Default
    private final Integer pathLenConstraint = 3;
}