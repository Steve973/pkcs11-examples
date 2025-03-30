package com.example.pki.model;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.security.cert.X509Certificate;
import java.util.Map;

/**
 * Represents a certificate with its associated attributes for PKCS12 storage
 */
public record PfxCertEntry(X509Certificate certificate, Map<ASN1ObjectIdentifier, ASN1Encodable> attributes, boolean trusted) {
}
