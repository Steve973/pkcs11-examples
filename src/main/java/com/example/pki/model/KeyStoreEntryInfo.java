package com.example.pki.model;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.Date;

/**
 * Value class containing detailed information about a keystore entry.
 */
@NoArgsConstructor
@Data
public class KeyStoreEntryInfo {
    private String alias;
    private String entryType;
    private String subject;
    private String issuer;
    private BigInteger serialNumber;
    private Date notBefore;
    private Date notAfter;
    private String publicKeyAlgorithm;
    private String privateKeyAlgorithm;
    private String privateKeyFormat;
    private String secretKeyAlgorithm;
    private String secretKeyFormat;
    private String signatureAlgorithm;
    private String extendedKeyUsage;
    private Date creationDate;
    private Certificate[] certificateChain;
    private String misc;

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Alias: ").append(alias).append("\n");
        sb.append("Type: ").append(entryType).append("\n");

        if (subject != null) {
            sb.append("Subject: ").append(subject).append("\n");
        }

        if (issuer != null) {
            sb.append("Issuer: ").append(issuer).append("\n");
        }

        if (serialNumber != null) {
            sb.append("Serial Number: ").append(serialNumber).append("\n");
        }

        if (notBefore != null && notAfter != null) {
            sb.append("Validity: ").append(notBefore).append(" to ").append(notAfter).append("\n");
        }

        if (publicKeyAlgorithm != null) {
            sb.append("Public Key Algorithm: ").append(publicKeyAlgorithm).append("\n");
        }

        if (privateKeyAlgorithm != null) {
            sb.append("Private Key Algorithm: ").append(privateKeyAlgorithm).append("\n");
        }

        if (privateKeyFormat != null) {
            sb.append("Private Key Format: ").append(privateKeyFormat).append("\n");
        }

        if (secretKeyAlgorithm != null) {
            sb.append("Secret Key Algorithm: ").append(secretKeyAlgorithm).append("\n");
        }

        if (signatureAlgorithm != null) {
            sb.append("Signature Algorithm: ").append(signatureAlgorithm).append("\n");
        }

        if (extendedKeyUsage != null) {
            sb.append("Extended Usage: ").append(extendedKeyUsage).append("\n");
        }

        if (creationDate != null) {
            sb.append("Creation Date: ").append(creationDate).append("\n");
        }

        if (certificateChain != null) {
            sb.append("Certificate Chain Length: ").append(certificateChain.length).append("\n");
        }

        if (misc != null) {
            sb.append("Miscellaneous: ").append(misc).append("\n");
        }

        return sb.toString();
    }
}
