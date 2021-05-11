package com.rahulahuja.biometricfingerprint

import android.content.SharedPreferences
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import java.security.InvalidKeyException
import java.security.KeyStore
import java.util.concurrent.Executor
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey


class MainActivity : AppCompatActivity(), View.OnClickListener {
    private lateinit var biometricLoginButton: Button
    private lateinit var executor: Executor
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo

    private lateinit var cipherInstance: Cipher
    private lateinit var generatedSecretKey: SecretKey

    private val KEY_NAME = "SomeKeyName"
    var keyPassword = "123456".toCharArray()

    private var PRIVATE_MODE = 0
    private val PREF_NAME = "biometric-fingerprint-added"
    private lateinit var biometricPref: SharedPreferences

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        biometricLoginButton = findViewById(R.id.biometric_login)
        biometricLoginButton.setOnClickListener(this)

        biometricPref = getSharedPreferences(PREF_NAME, PRIVATE_MODE)

        try {
            if (!biometricPref.getBoolean(PREF_NAME, false)) {
                generateKey()
                cipherInstance = getCipher()
                generatedSecretKey = getSecretKey()

                executor = ContextCompat.getMainExecutor(this)
                biometricPrompt = BiometricPrompt(this, executor,
                        object : BiometricPrompt.AuthenticationCallback() {
                            override fun onAuthenticationError(errorCode: Int,
                                                               errString: CharSequence) {
                                super.onAuthenticationError(errorCode, errString)
                                Toast.makeText(applicationContext,
                                        "Authentication error: $errString", Toast.LENGTH_SHORT)
                                        .show()
                            }

                            override fun onAuthenticationSucceeded(
                                    result: BiometricPrompt.AuthenticationResult) {
                                super.onAuthenticationSucceeded(result)
                                Toast.makeText(applicationContext,
                                        "Authentication succeeded!", Toast.LENGTH_SHORT)
                                        .show()
                            }

                            override fun onAuthenticationFailed() {
                                super.onAuthenticationFailed()
                                Toast.makeText(applicationContext, "Authentication failed",
                                        Toast.LENGTH_SHORT)
                                        .show()
                            }
                        })

                promptInfo = BiometricPrompt.PromptInfo.Builder()
                        .setTitle("Biometric login")
                        .setSubtitle("Log in using your biometric credential")
                        .setNegativeButtonText("Cancel")
                        .build()
            } else {
                throw KeyPermanentlyInvalidatedException()
            }
        } catch (e: KeyPermanentlyInvalidatedException) {
            onCaughtKeyPermanentlyInvalidatedException(e)
        }
    }

    private fun onCaughtKeyPermanentlyInvalidatedException(e: KeyPermanentlyInvalidatedException) {
        Log.e("Biometric Finger", "New fingerprint added, key has been changed >>>>> \n ${e.message}")
        Toast.makeText(this, "New fingerprint added, cannot proceed", Toast.LENGTH_LONG).show()
        biometricPref.edit().putBoolean(PREF_NAME, true).apply()
//        generateKey()
    }

    private fun generateKey() {
        generateSecretKey(KeyGenParameterSpec.Builder(
                KEY_NAME,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
                .build())
    }

    private fun generateSecretKey(keyGenParameterSpec: KeyGenParameterSpec) {
        val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        keyGenerator.init(keyGenParameterSpec)
        keyGenerator.generateKey()
    }

    private fun getSecretKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        return keyStore.getKey(KEY_NAME, keyPassword) as SecretKey
    }

    private fun getCipher(): Cipher {
        return Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                + KeyProperties.BLOCK_MODE_CBC + "/"
                + KeyProperties.ENCRYPTION_PADDING_PKCS7)
    }

    override fun onClick(v: View?) {
        when (v?.id) {
            R.id.biometric_login -> {
                try {
                    if (biometricPref.getBoolean(PREF_NAME, false)) {
                        throw KeyPermanentlyInvalidatedException()
                    }
                    cipherInstance.init(Cipher.ENCRYPT_MODE, generatedSecretKey)

                    biometricPrompt.authenticate(promptInfo)
                    Log.e("Biometric Finger", "executed...........")
                } catch (e: KeyPermanentlyInvalidatedException) {
                    onCaughtKeyPermanentlyInvalidatedException(e)
                } catch (e: InvalidKeyException) {
                    Log.e("Biometric Finger", "Invalid Key Exception...........\n ${e.message}")
                }
            }
        }
    }
}