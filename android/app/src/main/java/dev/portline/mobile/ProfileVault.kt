package dev.portline.mobile

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

// A device-local encrypted profile. Backups are disabled in the manifest.
object ProfileVault {
    private const val alias = "PortlineLocalProfileAES"
    private const val store = "portline_private"
    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256).build())
        return generator.generateKey()
    }
    fun save(context: Context, encoded: String) {
        PortlineProfile.decode(encoded)
        saveSecret(context, "profile", encoded)
    }

    fun load(context: Context): String? = loadSecret(context, "profile")

    fun saveSecret(context: Context, prefKey: String, plain: String) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val payload = cipher.iv + cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
        context.getSharedPreferences(store, Context.MODE_PRIVATE).edit()
            .putString(prefKey, Base64.encodeToString(payload, Base64.NO_WRAP)).apply()
    }

    fun loadSecret(context: Context, prefKey: String): String? {
        val saved = context.getSharedPreferences(store, Context.MODE_PRIVATE).getString(prefKey, null) ?: return null
        val raw = Base64.decode(saved, Base64.NO_WRAP)
        require(raw.size > 12) { "Повреждённые данные в хранилище" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, raw.copyOfRange(0, 12)))
        return String(cipher.doFinal(raw.copyOfRange(12, raw.size)), Charsets.UTF_8)
    }
}
