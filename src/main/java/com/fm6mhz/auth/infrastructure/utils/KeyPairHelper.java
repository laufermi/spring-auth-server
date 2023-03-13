package com.fm6mhz.auth.infrastructure.utils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class KeyPairHelper {

    public static KeyPair generateRsaKey(String algorithm, int keySize) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
            keyPairGenerator.initialize(keySize);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
