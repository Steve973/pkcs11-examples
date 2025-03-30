package com.example.pki.bcfips;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.util.BasicEntropySourceProvider;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

import java.security.Provider;
import java.security.SecureRandom;

public class ProviderUtil {

    public static final Provider BC_PROVIDER = new BouncyCastleFipsProvider();
    public static final String TRUSTED_KEY_USAGE_OID = "2.16.840.1.113894.746875.1.1";
    public static final String ANY_EXTENDED_KEY_USAGE_OID = "2.5.29.37.0";

    static {
        CryptoServicesRegistrar.setSecureRandom(
                FipsDRBG.SHA512.fromEntropySource(
                                new BasicEntropySourceProvider(new SecureRandom(), true))
                        .setSecurityStrength(256)
                        .setEntropyBitsRequired(256)
                        .build(null, true));
    }
}
