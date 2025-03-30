package com.example.pki.stores;

import com.example.pki.model.KeyStoreEntryInfo;

import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class EntryInfoUtil {

    static void prepareEntryInfo(KeyStore.Entry entry, X509Certificate cert, KeyStoreEntryInfo info)
            throws CertificateParsingException {
        if (cert != null) {
            info.setSubject(cert.getSubjectX500Principal().getName());
            info.setIssuer(cert.getIssuerX500Principal().getName());
            info.setSerialNumber(cert.getSerialNumber());
            info.setNotBefore(cert.getNotBefore());
            info.setNotAfter(cert.getNotAfter());
            info.setPublicKeyAlgorithm(cert.getPublicKey().getAlgorithm());
            info.setSignatureAlgorithm(cert.getSigAlgName());
            info.setExtendedKeyUsage(cert.getExtendedKeyUsage() != null ?
                    String.join(", ", cert.getExtendedKeyUsage()) :
                    "None");
        }
        if (entry != null) {
            String attrInfo = Optional.ofNullable(entry.getAttributes())
                    .filter(a -> !a.isEmpty())
                    .map(attributes -> attributes.stream()
                            .map(a -> a.getName() + "->" + a.getValue())
                            .collect(Collectors.joining(", ")))
                    .orElse(null);
            info.setMisc(attrInfo);
        }
    }

    static void processKeyEntry(KeyStore keyStore, KeyStore.Entry entry, KeyStoreEntryInfo info,
                                        String alias, char[] password) throws Exception {
        info.setEntryType("PrivateKeyEntry");
        Certificate[] chain = keyStore.getCertificateChain(alias);
        if (chain != null) {
            info.setCertificateChain(chain);
            if (chain.length > 0 && chain[0] instanceof X509Certificate cert) {
                prepareEntryInfo(entry, cert, info);
            }
        }
        try {
            Key key = keyStore.getKey(alias, password);
            if (key instanceof PrivateKey) {
                info.setPrivateKeyAlgorithm(key.getAlgorithm());
                info.setPrivateKeyFormat(key.getFormat());
            }
        } catch (Exception e) {
            info.setPrivateKeyAlgorithm("Unknown (access denied)");
        }
    }

    static void processCertEntry(KeyStore keyStore, KeyStore.Entry entry, KeyStoreEntryInfo info,
                                         String alias) throws Exception {
        info.setEntryType("TrustedCertificateEntry");
        Certificate cert = keyStore.getCertificate(alias);
        if (cert instanceof X509Certificate x509) {
            prepareEntryInfo(entry, x509, info);
        }
    }

    static List<KeyStoreEntryInfo> processKeyStore(KeyStore keyStore, char[] password) throws Exception {
        List<KeyStoreEntryInfo> entries = new ArrayList<>();
        Enumeration<String> aliasEnum = keyStore.aliases();
        while (aliasEnum.hasMoreElements()) {
            String alias = aliasEnum.nextElement();
            KeyStore.Entry entry;
            KeyStoreEntryInfo info = new KeyStoreEntryInfo();
            info.setAlias(alias);
            if (keyStore.isKeyEntry(alias)) {
                entry = keyStore.getEntry(alias, new KeyStore.PasswordProtection(password));
                EntryInfoUtil.processKeyEntry(keyStore, entry, info, alias, password);
            } else if (keyStore.isCertificateEntry(alias)) {
                entry = keyStore.getEntry(alias, null);
                EntryInfoUtil.processCertEntry(keyStore, entry, info, alias);
            } else {
                entry = keyStore.getEntry(alias, null);
                info.setEntryType("Unknown");
                EntryInfoUtil.prepareEntryInfo(entry, null, info);
            }
            entries.add(info);
        }
        return entries;
    }
}
