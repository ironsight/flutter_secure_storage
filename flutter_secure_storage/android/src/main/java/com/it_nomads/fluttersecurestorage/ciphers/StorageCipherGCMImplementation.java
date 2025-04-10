package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.RequiresApi;

import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class StorageCipherGCMImplementation implements StorageCipher {

    private static final int keySize = 16; // AES-128
    private static final String KEY_ALGORITHM = "AES";
    private static final String SHARED_PREFERENCES_NAME = "FlutterSecureKeyStorage";
    private static final int AUTHENTICATION_TAG_SIZE = 128;

    private final Cipher cipher;
    private final SecureRandom secureRandom;
    private Key secretKey;

    public StorageCipherGCMImplementation(Context context, KeyCipher rsaCipher) throws Exception {
        secureRandom = new SecureRandom();
        String aesPreferencesKey = getAESPreferencesKey();

        SharedPreferences preferences = context.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = preferences.edit();

        String aesKey = preferences.getString(aesPreferencesKey, null);

        cipher = getCipher();

        if (aesKey != null) {
            byte[] encrypted;
            try {
                encrypted = Base64.decode(aesKey, Base64.DEFAULT);
                secretKey = rsaCipher.unwrap(encrypted, KEY_ALGORITHM);
                return;
            } catch (Exception e) {
                Log.e("StorageCipherGCMImpl", "unwrap key failed, creating new key", e);
                // If unwrap fails (e.g., RSA key changed), proceed to create a new AES key
            }
        }

        // Create and store a new AES key if none existed or unwrap failed
        byte[] key = new byte[keySize];
        secureRandom.nextBytes(key);
        secretKey = new SecretKeySpec(key, KEY_ALGORITHM);

        byte[] encryptedKey = rsaCipher.wrap(secretKey);
        editor.putString(aesPreferencesKey, Base64.encodeToString(encryptedKey, Base64.DEFAULT));
        editor.apply();
    }

    // Method previously inherited
    protected String getAESPreferencesKey() {
        // Use the specific key intended for GCM to avoid conflicts if migrating
        // from an old CBC implementation.
        return "VGhpcyBpcyB0aGUga2V5IGZvcihBIHNlY3XyZZBzdG9yYWdlIEFFUyBLZXkK";
    }

    @Override
    protected Cipher getCipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    // Method previously inherited + GCM specific size
    protected int getIvSize() {
        return 12; // Recommended IV size for GCM
    }

    // Method previously inherited + GCM specific spec
    @RequiresApi(api = Build.VERSION_CODES.KITKAT) // GCMParameterSpec requires API 19+
    @Override
    protected AlgorithmParameterSpec getParameterSpec(byte[] iv) {
        return new GCMParameterSpec(AUTHENTICATION_TAG_SIZE, iv);
    }

    // Encrypt method previously inherited, adapted for GCM IV
    @Override
    public byte[] encrypt(byte[] input) throws Exception {
        byte[] iv = new byte[getIvSize()]; // GCM uses 12-byte IV
        secureRandom.nextBytes(iv);

        AlgorithmParameterSpec gcmParameterSpec = getParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);

        byte[] payload = cipher.doFinal(input);
        byte[] combined = new byte[iv.length + payload.length];

        // Prepend IV to the ciphertext
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(payload, 0, combined, iv.length, payload.length);

        return combined;
    }

    // Decrypt method previously inherited, adapted for GCM IV
    @Override
    public byte[] decrypt(byte[] input) throws Exception {
        byte[] iv = new byte[getIvSize()]; // GCM uses 12-byte IV
        System.arraycopy(input, 0, iv, 0, iv.length);
        AlgorithmParameterSpec gcmParameterSpec = getParameterSpec(iv);

        int payloadSize = input.length - getIvSize();
        byte[] payload = new byte[payloadSize];
        System.arraycopy(input, iv.length, payload, 0, payloadSize);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

        return cipher.doFinal(payload);
    }

}
