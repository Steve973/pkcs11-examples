package com.example.pki.model;

import lombok.*;
import lombok.experimental.SuperBuilder;
import org.bouncycastle.jcajce.spec.DSADomainParametersGenerationParameterSpec;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;

import static com.example.pki.bcfips.ProviderUtil.BC_PROVIDER;

/**
 * Specification for DSA key generation.
 */
@EqualsAndHashCode(callSuper = true)
@Data
@SuperBuilder
public class DsaKeySpec extends KeySpec {

    /**
     * Enum defining the standard DSA key sizes.
     */
    @Getter
    @RequiredArgsConstructor
    public enum KeySize {

        /**
         * 1024-bit key size (legacy, not recommended for new applications)
         */
        BITS_1024(1024, 160),
        
        /**
         * 2048-bit key size (minimum recommended for modern applications)
         */
        BITS_2048(2048, 224),
        
        /**
         * 3072-bit key size (recommended for high-security applications)
         */
        BITS_3072(3072, 256);
        
        private final int pLen;

        private final int qLen;
    }
    
    /**
     * Key size specification using standard DSA key sizes
     */
    @Builder.Default
    private KeySize keySize = KeySize.BITS_3072;

    @Builder.Default
    private String signatureAlgorithm = "SHA384withDSA";

    @Builder.Default
    private String keyPairAlgorithm = "DSA";

    @Override
    public AlgorithmParameterSpec getAlgorithmParameterSpec() throws Exception {
        AlgorithmParameterGenerator algGen = AlgorithmParameterGenerator.getInstance(keyPairAlgorithm, BC_PROVIDER);
        algGen.init(new DSADomainParametersGenerationParameterSpec(keySize.pLen, keySize.qLen, keySize.qLen));
        AlgorithmParameters dsaParams = algGen.generateParameters();
        return dsaParams.getParameterSpec(DSAParameterSpec.class);
    }
}