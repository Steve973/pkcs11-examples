package com.example.pki.stores;

import com.example.pki.bcfips.ProviderUtil;
import com.example.pki.model.KeyStoreEntryInfo;
import com.example.pki.model.PfxCertEntry;
import com.example.pki.model.PfxKeyEntry;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.example.pki.bcfips.ProviderUtil.BC_PROVIDER;

@Slf4j
public class Pkcs12Util {

    private static PKCS12SafeBagBuilder createSafeBagBuilder(X509Certificate cert,
            Map<ASN1ObjectIdentifier, ASN1Encodable> attributes) throws IOException {
        return attributes.entrySet().stream()
                .reduce(
                        new JcaPKCS12SafeBagBuilder(cert),
                        (builder, entry) -> (JcaPKCS12SafeBagBuilder) builder.addBagAttribute(entry.getKey(), entry.getValue()),
                        (b1, b2) -> b1);
    }

    /**
     * Creates PKCS12 safe bags for certificates with customizable attributes
     *
     * @param certEntries List of certificate entries in the order they should be added to the PKCS12 store
     * @return Array of PKCS12SafeBag objects representing the certificates
     */
    public static PKCS12SafeBag[] createCertificateSafeBags(List<PfxCertEntry> certEntries) {
        return certEntries.stream()
                .peek(ce -> {
                    if (ce.trusted()) {
                        ce.attributes().put(
                                new ASN1ObjectIdentifier(ProviderUtil.TRUSTED_KEY_USAGE_OID),
                                new ASN1ObjectIdentifier(ProviderUtil.ANY_EXTENDED_KEY_USAGE_OID));
                    }
                })
                .map(entry -> {
                    try {
                        return createSafeBagBuilder(entry.certificate(), entry.attributes()).build();
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }
                })
                .toArray(PKCS12SafeBag[]::new);
    }

    private static Optional<PKCS12SafeBagBuilder> createPrivateKeySafeBagBuilder(PrivateKey privKey, char[] passwd) {
        try {
            return Optional.of(
                    new JcaPKCS12SafeBagBuilder(
                            privKey,
                            new JcePKCSPBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC)
                                    .setProvider(BC_PROVIDER)
                                    .build(passwd)));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private static PKCS12SafeBag createKeySafeBag(PrivateKey privKey,
                                                  Map<ASN1ObjectIdentifier, ASN1Encodable> attributes,
                                                  char[] passwd) throws IOException {
        return createPrivateKeySafeBagBuilder(privKey, passwd)
                .map(builder -> attributes.entrySet().stream()
                        .reduce(
                                builder,
                                (b, entry) -> b.addBagAttribute(entry.getKey(), entry.getValue()),
                                (b1, b2) -> b1))
                .map(PKCS12SafeBagBuilder::build)
                .orElseThrow(() -> new IOException("Failed to create key safe bag"));
    }

    private static OutputEncryptor createEncryptor(char[] passwd) throws Exception {
        return new JcePKCSPBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC)
                .setProvider(BC_PROVIDER)
                .build(passwd);
    }

    /**
     * Creates a PKCS#12 file with fully customizable attributes
     *
     * @param passwd Password to protect the PKCS#12 file
     * @param privateKeyEntries The private key entries to include
     * @param certEntries List of certificate entries in the order they should be added
     * @return Encoded PKCS#12 data
     */
    public static byte[] createPfxStore(char[] passwd,
                                        List<PfxKeyEntry> privateKeyEntries,
                                        List<PfxCertEntry> certEntries) throws Exception {
        PKCS12SafeBag[] certSafeBags = createCertificateSafeBags(certEntries);
        PKCS12PfxPduBuilder pfxPduBuilder = new PKCS12PfxPduBuilder();
        pfxPduBuilder.addEncryptedData(createEncryptor(passwd), certSafeBags);
        if (privateKeyEntries != null && !privateKeyEntries.isEmpty()) {
            for (PfxKeyEntry entry : privateKeyEntries) {
                PKCS12SafeBag keySafeBag = createKeySafeBag(entry.privateKey(), entry.attributes(), passwd);
                pfxPduBuilder.addData(keySafeBag);
            }
        }
        return pfxPduBuilder.build(new JcePKCS12MacCalculatorBuilder().setProvider(BC_PROVIDER), passwd)
                .getEncoded();
    }

    /**
     * Get info for all entries in the PKCS#11 keystore.
     *
     * @param keyStore the keystore to use
     * @param password Password for the keystore
     * @return List of aliases in the keystore
     */
    public static List<KeyStoreEntryInfo> listKeyStoreEntries(KeyStore keyStore, char[] password) {
        try {
            return EntryInfoUtil.processKeyStore(keyStore, password);
        } catch (Exception e) {
            throw new RuntimeException("Failed to list PKCS#11 keystore entries", e);
        }
    }
}
