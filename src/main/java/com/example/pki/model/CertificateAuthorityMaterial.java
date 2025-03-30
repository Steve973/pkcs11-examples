package com.example.pki.model;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

public record CertificateAuthorityMaterial(KeyPair rootKeyPair, String rootSigAlgName, X509Certificate rootCertificate,
                                           KeyPair intermediateKeyPair, String intermediateSigAlgName, X509Certificate intermediateCertificate,
                                           X509Certificate[] caChain) {
}