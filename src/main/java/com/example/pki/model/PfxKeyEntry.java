package com.example.pki.model;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.security.PrivateKey;
import java.util.Map;

/**
 * Represents a private key with its associated attributes for PKCS12 storage
 */
public record PfxKeyEntry(PrivateKey privateKey, Map<ASN1ObjectIdentifier, ASN1Encodable> attributes) {
}
