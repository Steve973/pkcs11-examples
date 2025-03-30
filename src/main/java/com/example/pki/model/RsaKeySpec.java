package com.example.pki.model;

import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.experimental.SuperBuilder;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

/**
 * Specification for RSA key generation.
 */
@EqualsAndHashCode(callSuper = true)
@Data
@SuperBuilder
public class RsaKeySpec extends KeySpec {

    /**
     * Enum defining the standard RSA key sizes.
     */
    @Getter
    @RequiredArgsConstructor
    public enum KeySize {

        /**
         * 2048-bit key size (minimum recommended for modern applications)
         */
        BITS_2048(2048),
        
        /**
         * 3072-bit key size (recommended for high-security applications)
         */
        BITS_3072(3072),
        
        /**
         * 4096-bit key size (recommended for very high-security applications)
         */
        BITS_4096(4096);
        
        private final int bits;
    }
    
    /**
     * Enum defining common RSA public exponents.
     */
    @Getter
    @RequiredArgsConstructor
    public enum PublicExponent {

        /**
         * Public exponent 3 (fastest, but requires careful implementation)
         */
        E_3(BigInteger.valueOf(3L)),
        
        /**
         * Public exponent 17 (good balance of security and performance)
         */
        E_17(BigInteger.valueOf(17L)),
        
        /**
         * Public exponent 65537 (F4) (most commonly used, recommended)
         */
        E_65537(BigInteger.valueOf(65537L));
        
        private final BigInteger value;
    }
    
    /**
     * Key size specification using standard RSA key sizes
     */
    @Builder.Default
    private KeySize keySize = KeySize.BITS_4096;
    
    /**
     * Public exponent specification using standard RSA public exponents
     */
    @Builder.Default
    private PublicExponent publicExponent = PublicExponent.E_65537;
    
    /**
     * Whether the key can be used for encryption
     */
    @Builder.Default
    private boolean canEncrypt = true;

    @Builder.Default
    private String signatureAlgorithm = "SHA384withRSA";

    @Builder.Default
    private String keyPairAlgorithm = "RSA";

    @Override
    public AlgorithmParameterSpec getAlgorithmParameterSpec() {
        return new RSAKeyGenParameterSpec(getKeySize().getBits(), publicExponent.getValue());
    }
}