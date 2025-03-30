package com.example.pki.model;

import lombok.*;
import lombok.experimental.SuperBuilder;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

/**
 * Specification for Elliptic Curve key generation.
 */
@EqualsAndHashCode(callSuper = true)
@Data
@SuperBuilder
public class EcKeySpec extends KeySpec {

    /**
     * Enum defining the standard elliptic curves.
     */
    @Getter
    @RequiredArgsConstructor
    public enum CurveName {

        /**
         * secp256r1 (NIST P-256) - 256-bit prime field curve
         * Provides 128-bit security level, suitable for most applications
         */
        SECP256R1("secp256r1"),
        
        /**
         * secp384r1 (NIST P-384) - 384-bit prime field curve
         * Provides 192-bit security level, suitable for high-security applications
         */
        SECP384R1("secp384r1"),
        
        /**
         * secp521r1 (NIST P-521) - 521-bit prime field curve
         * Provides 256-bit security level, suitable for very high-security applications
         */
        SECP521R1("secp521r1");
        
        private final String ecName;
    }

    /**
     * Named curve to use (e.g., "secp256r1", "secp384r1", "secp521r1")
     */
    @Builder.Default
    private CurveName curveName = CurveName.SECP521R1;
    
    /**
     * Whether the key can be used for key agreement (ECDH)
     */
    @Builder.Default
    private boolean canDerive = true;

    @Builder.Default
    private String signatureAlgorithm = "SHA384withECDSA";

    @Builder.Default
    private String keyPairAlgorithm = "EC";

    @Override
    public AlgorithmParameterSpec getAlgorithmParameterSpec() {
        return new ECGenParameterSpec(getCurveName().getEcName());
    }
}