package com.example.pki.model;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import lombok.Getter;

/**
 * Enum representing standard X.509 Key Usage extension values.
 * These values define the purpose of the key contained in the certificate.
 */
@Getter
public enum KeyUsageType {

    /**
     * The key may be used for digital signatures.
     */
    DIGITAL_SIGNATURE("digitalSignature"),
    
    /**
     * The key may be used for non-repudiation.
     */
    NON_REPUDIATION("nonRepudiation"),
    
    /**
     * The key may be used for key encipherment.
     */
    KEY_ENCIPHERMENT("keyEncipherment"),
    
    /**
     * The key may be used for data encipherment.
     */
    DATA_ENCIPHERMENT("dataEncipherment"),
    
    /**
     * The key may be used for key agreement.
     */
    KEY_AGREEMENT("keyAgreement"),
    
    /**
     * The key may be used for certificate signing.
     */
    KEY_CERT_SIGN("keyCertSign"),
    
    /**
     * The key may be used for CRL signing.
     */
    CRL_SIGN("cRLSign"),
    
    /**
     * The key may be used only for enciphering data.
     */
    ENCIPHER_ONLY("encipherOnly"),
    
    /**
     * The key may be used only for deciphering data.
     */
    DECIPHER_ONLY("decipherOnly");
    
    /**
     * The string representation as used in X.509 certificates.
     */
    private final String x509Name;

    /**
     * Map of string representations to KeyUsage enum values for reverse lookups.
     */
    private static final Map<String, KeyUsageType> nameToEnum;
    
    static {
        nameToEnum = new HashMap<>();
        for (KeyUsageType usage : values()) {
            nameToEnum.put(usage.getX509Name().toLowerCase(), usage);
        }
    }
    
    /**
     * Create the instance with the X.509 string representation.
     */
    KeyUsageType(String x509Name) {
        this.x509Name = x509Name;
    }
    
    /**
     * Returns the OID bit position for this key usage as defined in RFC 5280.
     * 
     * @return the bit position (0-8)
     */
    public int getBitPosition() {
        return ordinal();
    }
    
    /**
     * Returns the KeyUsage enum value from its string representation.
     * 
     * @param name the string representation
     * @return the corresponding KeyUsage enum value
     * @throws IllegalArgumentException if the name doesn't match any KeyUsage
     */
    public static KeyUsageType fromString(String name) {
        return Optional.ofNullable(name)
            .map(String::trim)
            .map(String::toLowerCase)
            .map(nameToEnum::get)
            .orElseThrow(() -> new IllegalArgumentException("Name must be one of: " +
                nameToEnum.keySet()
                    .stream()
                    .collect(Collectors.joining(", "))));
    }
}