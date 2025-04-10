package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.os.Build;

import androidx.annotation.RequiresApi;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;

public class StorageCipherGCMImplementation extends StorageCipher18Implementation {

    private static final int AUTHENTICATION_TAG_SIZE = 128;

    public StorageCipherGCMImplementation(Context context, KeyCipher rsaCipher) throws Exception {
        super(context, rsaCipher);
    }

    @Override
    protected String getAESPreferencesKey() {
        return "VGhpcyBpcyB0aGUga2V5IGZvcihBIHNlY3XyZZBzdG9yYWdlIEFFUyBLZXkK";
    }

    @Override
    protected Cipher getCipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    @Override
    protected int getIvSize() {
        return 12; // Recommended IV size for GCM
    }

    @RequiresApi(api = Build.VERSION_CODES.KITKAT) // GCMParameterSpec requires API 19+
    @Override
    protected AlgorithmParameterSpec getParameterSpec(byte[] iv) {
        return new GCMParameterSpec(AUTHENTICATION_TAG_SIZE, iv);
    }

}
