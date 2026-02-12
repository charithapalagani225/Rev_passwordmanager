package com.revpasswordmanager.util;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Base64;

public class CryptoUtilTest {

    @Test
    void testHashAndVerifyPassword() {
        String password = "mySecretPassword";
        String hash = CryptoUtil.hashPassword(password);

        assertNotNull(hash);
        assertNotEquals(password, hash);
        assertTrue(CryptoUtil.verifyPassword(password, hash));
        assertFalse(CryptoUtil.verifyPassword("wrongPassword", hash));
    }

    @Test
    void testEncryptAndDecrypt() {
        String originalText = "Secret Data";
        String password = "masterPassword";
        byte[] key = CryptoUtil.deriveKey(password);

        String encrypted = CryptoUtil.encrypt(originalText, key);
        assertNotNull(encrypted);
        assertNotEquals(originalText, encrypted);

        String decrypted = CryptoUtil.decrypt(encrypted, key);
        assertEquals(originalText, decrypted);
    }

    @Test
    void testDeriveKey() {
        String password = "testPassword";
        byte[] key1 = CryptoUtil.deriveKey(password);
        byte[] key2 = CryptoUtil.deriveKey(password);

        assertNotNull(key1);
        assertNotNull(key2);
        assertArrayEquals(key1, key2);

        byte[] key3 = CryptoUtil.deriveKey("differentPassword");
        assertFalse(java.util.Arrays.equals(key1, key3));
    }
}
