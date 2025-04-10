package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;

import java.util.Map;

enum KeyCipherAlgorithm {
    RSA_ECB_PKCS1Padding(RSACipher18Implementation::new, 1),
    @SuppressWarnings({"UnusedDeclaration"})
    RSA_ECB_OAEPwithSHA_256andMGF1Padding(RSACipherOAEPImplementation::new, Build.VERSION_CODES.M);
    final KeyCipherFunction keyCipher;
    final int minVersionCode;

    KeyCipherAlgorithm(KeyCipherFunction keyCipher, int minVersionCode) {
        this.keyCipher = keyCipher;
        this.minVersionCode = minVersionCode;
    }
}

enum StorageCipherAlgorithm {
    // Only GCM is supported now (minSdk = 23)
    AES_GCM_NoPadding(StorageCipherGCMImplementation::new, Build.VERSION_CODES.M);
    final StorageCipherFunction storageCipher;
    final int minVersionCode;

    StorageCipherAlgorithm(StorageCipherFunction storageCipher, int minVersionCode) {
        this.storageCipher = storageCipher;
        this.minVersionCode = minVersionCode;
    }
}

@FunctionalInterface
interface StorageCipherFunction {
    StorageCipher apply(Context context, KeyCipher keyCipher) throws Exception;
}

@FunctionalInterface
interface KeyCipherFunction {
    KeyCipher apply(Context context) throws Exception;
}

public class StorageCipherFactory {
    private static final String ELEMENT_PREFERENCES_ALGORITHM_PREFIX = "FlutterSecureSAlgorithm";
    private static final String ELEMENT_PREFERENCES_ALGORITHM_KEY = ELEMENT_PREFERENCES_ALGORITHM_PREFIX + "Key";
    private static final String ELEMENT_PREFERENCES_ALGORITHM_STORAGE = ELEMENT_PREFERENCES_ALGORITHM_PREFIX + "Storage";

    // Defaults
    private static final KeyCipherAlgorithm DEFAULT_KEY_ALGORITHM = KeyCipherAlgorithm.RSA_ECB_PKCS1Padding;
    private static final StorageCipherAlgorithm DEFAULT_STORAGE_ALGORITHM = StorageCipherAlgorithm.AES_GCM_NoPadding;

    // Note: savedStorageAlgorithm might still read AES_CBC_PKCS7Padding from old prefs, but it won't be used
    // for new encryption/decryption if requiresReEncryption() is handled correctly.
    private final KeyCipherAlgorithm savedKeyAlgorithm;
    private final StorageCipherAlgorithm savedStorageAlgorithm;
    private final KeyCipherAlgorithm currentKeyAlgorithm;
    private final StorageCipherAlgorithm currentStorageAlgorithm;

    public StorageCipherFactory(SharedPreferences source, Map<String, Object> options) {
        // === Saved Algorithm Determination ===
        // Read saved algorithms, using GCM as the default if the preference key is missing
        // Note: This might try to read "AES_CBC_PKCS7Padding" from old prefs, causing an exception if that enum value is removed entirely.
        // Keeping the enum value but making it unused in selection logic is safer for migration.
        // If strict cleanup is desired and migration from CBC isn't needed, the AES_CBC entry could be fully removed.
        String savedStorageAlgoName = source.getString(ELEMENT_PREFERENCES_ALGORITHM_STORAGE, DEFAULT_STORAGE_ALGORITHM.name());
        try {
            savedStorageAlgorithm = StorageCipherAlgorithm.valueOf(savedStorageAlgoName);
        } catch (IllegalArgumentException e) {
            // Handle case where old prefs had AES_CBC_PKCS7Padding which no longer exists
            // or if prefs are corrupted. Default to GCM.
            // Log.w("StorageCipherFactory", "Invalid saved storage algorithm '" + savedStorageAlgoName + "', defaulting to GCM.");
            savedStorageAlgorithm = DEFAULT_STORAGE_ALGORITHM;
        }
        savedKeyAlgorithm = KeyCipherAlgorithm.valueOf(source.getString(ELEMENT_PREFERENCES_ALGORITHM_KEY, DEFAULT_KEY_ALGORITHM.name()));


        // === Current Algorithm Determination ===

        // --- Determine and Set Current Storage Algorithm ---
        // Always use GCM as minSdk is 23+. Check if options specify something else (though only GCM is valid now).
        String storageOptionValue = (String) options.get("storageCipherAlgorithm");
        StorageCipherAlgorithm requestedStorageAlgorithm = DEFAULT_STORAGE_ALGORITHM;
        if (storageOptionValue != null) {
            try {
                requestedStorageAlgorithm = StorageCipherAlgorithm.valueOf(storageOptionValue);
            } catch (IllegalArgumentException e) {
                // Log.w("StorageCipherFactory", "Invalid storage algorithm option '" + storageOptionValue + "', using default GCM.");
                requestedStorageAlgorithm = DEFAULT_STORAGE_ALGORITHM;
            }
        }
        // Since minSdk=23, requested algorithm's minVersionCode check isn't strictly needed, but good practice.
        // And currently, only AES_GCM_NoPadding is defined anyway.
        currentStorageAlgorithm = (requestedStorageAlgorithm.minVersionCode <= Build.VERSION.SDK_INT) ? requestedStorageAlgorithm : DEFAULT_STORAGE_ALGORITHM;


        // --- Determine and Set Current Key Algorithm ---
        // Logic remains the same, defaulting to RSA_ECB_PKCS1Padding unless option overrides and is supported.
        final KeyCipherAlgorithm currentKeyAlgorithmTmp = KeyCipherAlgorithm.valueOf(getFromOptionsWithDefault(options, "keyCipherAlgorithm", DEFAULT_KEY_ALGORITHM.name()));
        currentKeyAlgorithm = (currentKeyAlgorithmTmp.minVersionCode <= Build.VERSION.SDK_INT) ? currentKeyAlgorithmTmp : DEFAULT_KEY_ALGORITHM;
    }

    private String getFromOptionsWithDefault(Map<String, Object> options, String key, String defaultValue) {
        final Object value = options.get(key);
        return value != null ? value.toString() : defaultValue;
    }

    public boolean requiresReEncryption() {
        // Re-encrypt if the key algorithm changed, or if the saved storage algorithm wasn't GCM
        return savedKeyAlgorithm != currentKeyAlgorithm || savedStorageAlgorithm != StorageCipherAlgorithm.AES_GCM_NoPadding;
    }

    // This method might fail if it tries to instantiate a StorageCipher for an algorithm
    // that no longer exists (like AES_CBC). Consider if this method is still needed
    // or how re-encryption handles reading old data.
    // For now, it assumes valueOf() would fail above if AES_CBC was read and the enum was removed.
    public StorageCipher getSavedStorageCipher(Context context) throws Exception {
        final KeyCipher keyCipher = savedKeyAlgorithm.keyCipher.apply(context);
        // If savedStorageAlgorithm could be AES_CBC, this line needs careful handling
        // if that enum value/implementation is removed.
        return savedStorageAlgorithm.storageCipher.apply(context, keyCipher);
    }

    public StorageCipher getCurrentStorageCipher(Context context) throws Exception {
        final KeyCipher keyCipher = currentKeyAlgorithm.keyCipher.apply(context);
        return currentStorageAlgorithm.storageCipher.apply(context, keyCipher);
    }

    public void storeCurrentAlgorithms(SharedPreferences.Editor editor) {
        editor.putString(ELEMENT_PREFERENCES_ALGORITHM_KEY, currentKeyAlgorithm.name());
        editor.putString(ELEMENT_PREFERENCES_ALGORITHM_STORAGE, currentStorageAlgorithm.name()); // Should always be GCM now
    }

    public void removeCurrentAlgorithms(SharedPreferences.Editor editor) {
        editor.remove(ELEMENT_PREFERENCES_ALGORITHM_KEY);
        editor.remove(ELEMENT_PREFERENCES_ALGORITHM_STORAGE);
    }
}
