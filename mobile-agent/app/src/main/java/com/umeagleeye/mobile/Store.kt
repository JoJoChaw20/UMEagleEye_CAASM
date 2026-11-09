package com.umeagleeye.mobile

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** The connection and what the app last did, in its private preferences. The API key is encrypted
 *  with a key kept in the Android Keystore (it never leaves the phone's secure hardware where the
 *  phone has it), so a backup or a copy of the preferences file does not reveal it. */
class Store(context: Context) {
    private val prefs = context.getSharedPreferences("agent", Context.MODE_PRIVATE)

    var apiUrl: String?
        get() = prefs.getString("api_url", null)
        set(v) = prefs.edit().putString("api_url", v).apply()
    var agentId: String?
        get() = prefs.getString("agent_id", null)
        set(v) = prefs.edit().putString("agent_id", v).apply()
    var apiKey: String?
        get() = prefs.getString("api_key_enc", null)?.let { runCatching { Secret.decrypt(it) }.getOrNull() }
        set(v) = prefs.edit().putString("api_key_enc", v?.let { Secret.encrypt(it) }).apply()

    val connected: Boolean get() = apiUrl != null && agentId != null && apiKey != null

    // The administrator's settings from the last heartbeat (the dashboard's Agents page)
    var inventoryOn: Boolean
        get() = prefs.getBoolean("inventory", true)
        set(v) = prefs.edit().putBoolean("inventory", v).apply()
    var inventoryInterval: Long
        get() = prefs.getLong("inventory_interval", DEFAULT_INVENTORY_INTERVAL)
        set(v) = prefs.edit().putLong("inventory_interval", v).apply()
    var sendApps: Boolean
        get() = prefs.getBoolean("inventory_user_software", false)
        set(v) = prefs.edit().putBoolean("inventory_user_software", v).apply()
    var policyVersion: String?
        get() = prefs.getString("policy_version", null)
        set(v) = prefs.edit().putString("policy_version", v).apply()

    var lastHeartbeatAt: Long
        get() = prefs.getLong("last_heartbeat_at", 0)
        set(v) = prefs.edit().putLong("last_heartbeat_at", v).apply()
    var lastHeartbeatOk: Boolean
        get() = prefs.getBoolean("last_heartbeat_ok", false)
        set(v) = prefs.edit().putBoolean("last_heartbeat_ok", v).apply()
    var lastInventoryAt: Long
        get() = prefs.getLong("last_inventory_at", 0)
        set(v) = prefs.edit().putLong("last_inventory_at", v).apply()
    var lastMessage: String?
        get() = prefs.getString("last_message", null)
        set(v) = prefs.edit().putString("last_message", v).apply()

    fun forget() {
        prefs.edit().clear().apply()
    }

    companion object {
        const val DEFAULT_INVENTORY_INTERVAL = 21600L          // 6 hours, as the computers' agent
    }
}

private object Secret {
    private const val ALIAS = "eagleeye-api-key"

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    fun encrypt(plain: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
        val sealed = cipher.iv + cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(sealed, Base64.NO_WRAP)
    }

    fun decrypt(text: String): String {
        val sealed = Base64.decode(text, Base64.NO_WRAP)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, sealed, 0, 12))
        return String(cipher.doFinal(sealed, 12, sealed.size - 12), Charsets.UTF_8)
    }
}
