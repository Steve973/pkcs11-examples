package com.example.pki.model;

import lombok.Builder;
import lombok.Data;
import lombok.experimental.SuperBuilder;

import java.security.spec.AlgorithmParameterSpec;

@Data
@SuperBuilder
public abstract class KeySpec {
    
    /**
     * Key label/alias for identification in the keystore
     */
    private final String keyLabel;
    
    /**
     * Whether the key is extractable
     */
    @Builder.Default
    private final boolean extractable = false;
    
    /**
     * Whether the key can be used for signing
     */
    @Builder.Default
    private final boolean canSign = true;

    /**
     * Gets the signature algorithm for this key specification.
     *
     * @return the signature algorithm
     */
    public abstract String getSignatureAlgorithm();

    /**
     * Gets the key pair algorithm for this key specification.
     *
     * @return the key pair algorithm
     */
    public abstract String getKeyPairAlgorithm();

    /**
     * Gets the algorithm parameter specification for this key specification.
     *
     * @return the algorithm parameter specification
     */
    public abstract AlgorithmParameterSpec getAlgorithmParameterSpec() throws Exception;
}