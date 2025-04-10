package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
// import android.util.Log; // Uncomment if adding Log.w calls

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

// Defines the available algorithms for encrypting/decrypting the actual stored value.
enum StorageCipherAlgorithm {
    // Re-add CBC for migration purposes, associated with the restored implementation.
    AES_CBC_PKCS7Padding(StorageCipher18Implementation::new, 1),
    // GCM is preferred on API 23+
    @SuppressWarnings({"UnusedDeclaration"})
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

    // Default algorithms to use if nothing is specified.
    private static final KeyCipherAlgorithm DEFAULT_KEY_ALGORITHM = KeyCipherAlgorithm.RSA_ECB_PKCS1Padding;
    // Use CBC as the legacy default for reading potentially missing preferences before SDK check.
    private static final StorageCipherAlgorithm LEGACY_DEFAULT_STORAGE_ALGORITHM = StorageCipherAlgorithm.AES_CBC_PKCS7Padding;

    private final KeyCipherAlgorithm savedKeyAlgorithm;
    private final StorageCipherAlgorithm savedStorageAlgorithm;
    private final KeyCipherAlgorithm currentKeyAlgorithm;
    private final StorageCipherAlgorithm currentStorageAlgorithm;

    public StorageCipherFactory(SharedPreferences source, Map<String, Object> options) {

        // Read the previously used storage algorithm. Default to legacy CBC if not found.
        // This ensures that if the pref is missing, requiresReEncryption will correctly trigger
        // if the current algorithm resolves to GCM.
        String savedStorageAlgoName = source.getString(ELEMENT_PREFERENCES_ALGORITHM_STORAGE, LEGACY_DEFAULT_STORAGE_ALGORITHM.name());
        StorageCipherAlgorithm tempSavedStorageAlgorithm;
        try {
            // Read the actual saved value.
            tempSavedStorageAlgorithm = StorageCipherAlgorithm.valueOf(savedStorageAlgoName);
        } catch (IllegalArgumentException e) {
            // Handle corrupted preference value, default to legacy CBC for the check.
            // Log.w("StorageCipherFactory", "Invalid saved storage algorithm value '" + savedStorageAlgoName + "', defaulting to CBC for check.");
            tempSavedStorageAlgorithm = LEGACY_DEFAULT_STORAGE_ALGORITHM;
        }
        savedStorageAlgorithm = tempSavedStorageAlgorithm;

        savedKeyAlgorithm = KeyCipherAlgorithm.valueOf(source.getString(ELEMENT_PREFERENCES_ALGORITHM_KEY, DEFAULT_KEY_ALGORITHM.name()));


        // === Current Algorithm Determination ===

        // --- Determine Target Storage Algorithm ---
        // Determine the storage algorithm to use for this session, preferring GCM on API 23+.
        StorageCipherAlgorithm targetStorageAlgorithm;
        String storageOptionValue = (String) options.get("storageCipherAlgorithm");

        if (storageOptionValue != null) {
            // Use algorithm from options if provided and valid.
            try {
                 targetStorageAlgorithm = StorageCipherAlgorithm.valueOf(storageOptionValue);
            } catch (IllegalArgumentException e) {
                // Invalid option, fall back to SDK-based default.
                // Log.w("StorageCipherFactory", "Invalid storage algorithm option '" + storageOptionValue + "', using SDK default.");
                targetStorageAlgorithm = getDefaultStorageAlgorithmForSdk();
            }
        } else {
            // No option - use best available default based on SDK version.
            targetStorageAlgorithm = getDefaultStorageAlgorithmForSdk();
        }

        // --- Validate and Set Current Storage Algorithm ---
        // Ensure the target algorithm is supported by the current SDK version. Fallback to CBC if not.
        // (This primarily handles requesting GCM on API < 23 via options, which shouldn't happen with minSdk=23)
        if (targetStorageAlgorithm.minVersionCode <= Build.VERSION.SDK_INT) {
            currentStorageAlgorithm = targetStorageAlgorithm;
        } else {
            currentStorageAlgorithm = StorageCipherAlgorithm.AES_CBC_PKCS7Padding;
            // Log.w("StorageCipherFactory", "Requested storage algorithm " + targetStorageAlgorithm + " not supported on API " + Build.VERSION.SDK_INT + ", falling back to CBC.");
        }


        // --- Determine and Set Current Key Algorithm ---
        final KeyCipherAlgorithm currentKeyAlgorithmTmp = KeyCipherAlgorithm.valueOf(getFromOptionsWithDefault(options, "keyCipherAlgorithm", DEFAULT_KEY_ALGORITHM.name()));
        currentKeyAlgorithm = (currentKeyAlgorithmTmp.minVersionCode <= Build.VERSION.SDK_INT) ? currentKeyAlgorithmTmp : DEFAULT_KEY_ALGORITHM;
    }

    // Helper method to get the best default storage algorithm based on SDK version
    private StorageCipherAlgorithm getDefaultStorageAlgorithmForSdk() {
        if (Build.VERSION.SDK_INT >= StorageCipherAlgorithm.AES_GCM_NoPadding.minVersionCode) {
            return StorageCipherAlgorithm.AES_GCM_NoPadding; // Prefer GCM on API 23+
        } else {
            return StorageCipherAlgorithm.AES_CBC_PKCS7Padding; // Fallback for older SDKs (relevant if minSdk was < 23)
        }
    }

    private String getFromOptionsWithDefault(Map<String, Object> options, String key, String defaultValue) {
        final Object value = options.get(key);
        return value != null ? value.toString() : defaultValue;
    }

    public boolean requiresReEncryption() {
        // Re-encrypt if the key algorithm changed OR if the storage algorithm changed.
        // This now correctly compares the actual saved algorithm (potentially CBC)
        // with the determined current algorithm (potentially GCM).
        return savedKeyAlgorithm != currentKeyAlgorithm || savedStorageAlgorithm != currentStorageAlgorithm;
    }

    /**
     * Creates a StorageCipher instance using the algorithms read from SharedPreferences.
     * Used for reading data during re-encryption.
     */
    public StorageCipher getSavedStorageCipher(Context context) throws Exception {
        final KeyCipher keyCipher = savedKeyAlgorithm.keyCipher.apply(context);
        // This should now work correctly as savedStorageAlgorithm can be AES_CBC_PKCS7Padding
        // and the corresponding implementation exists.
        return savedStorageAlgorithm.storageCipher.apply(context, keyCipher);
    }

    /**
     * Creates a StorageCipher instance using the currently determined algorithms.
     */
    public StorageCipher getCurrentStorageCipher(Context context) throws Exception {
        final KeyCipher keyCipher = currentKeyAlgorithm.keyCipher.apply(context);
        return currentStorageAlgorithm.storageCipher.apply(context, keyCipher);
    }

    /**
     * Saves the names of the current algorithms to SharedPreferences.
     */
    public void storeCurrentAlgorithms(SharedPreferences.Editor editor) {
        editor.putString(ELEMENT_PREFERENCES_ALGORITHM_KEY, currentKeyAlgorithm.name());
        editor.putString(ELEMENT_PREFERENCES_ALGORITHM_STORAGE, currentStorageAlgorithm.name());
    }

    /**
     * Removes the saved algorithm names from SharedPreferences.
     */
    public void removeCurrentAlgorithms(SharedPreferences.Editor editor) {
        editor.remove(ELEMENT_PREFERENCES_ALGORITHM_KEY);
        editor.remove(ELEMENT_PREFERENCES_ALGORITHM_STORAGE);
    }
}
