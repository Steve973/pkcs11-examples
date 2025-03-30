package com.example.pki.model;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public record CertKeyPair(X509Certificate certificate, PrivateKey privateKey) {
}
