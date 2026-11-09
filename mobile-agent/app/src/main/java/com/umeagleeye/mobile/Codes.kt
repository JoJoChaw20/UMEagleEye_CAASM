package com.umeagleeye.mobile

import org.json.JSONObject
import java.security.MessageDigest
import java.time.LocalDate
import java.time.format.DateTimeParseException
import java.time.temporal.ChronoUnit
import java.util.Base64

/** A code from the dashboard's Agents page (the same formats as agent-gui/eagleeye/enrol.py):
 *  "EE1." + base64url(JSON {u, i, k}) connects one agent; "EE2." + base64url(JSON {u, t}) is an
 *  install code, exchanged once at POST /enrolment/enrol for an agent of this phone's own. */
sealed class Code {
    data class Agent(val apiUrl: String, val agentId: String, val apiKey: String) : Code()
    data class Install(val apiUrl: String, val token: String) : Code()
}

class CodeError(message: String) : Exception(message)

object Codes {
    private val UUID = Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
    private val TOKEN = Regex("^[0-9a-f]{64}$")
    private const val DAMAGED = "The code is incomplete or damaged. Copy the whole code again."

    /** Spaces, line breaks and quotes from copying it out of a chat or an email are ignored. */
    fun parse(text: String): Code {
        val raw = text.filterNot { it.isWhitespace() }.trim('"', '\'')
        if (raw.isEmpty()) throw CodeError("Paste the connection code from the dashboard's Agents page first.")
        val install = raw.startsWith("EE2.")
        if (!install && !raw.startsWith("EE1.")) {
            throw CodeError("This is not an EagleEye code: it starts with EE1. or EE2. Copy it again from the dashboard's Agents page.")
        }
        val data = try {
            JSONObject(String(Base64.getUrlDecoder().decode(raw.substring(4).trimEnd('=')), Charsets.UTF_8))
        } catch (e: Exception) {
            throw CodeError(DAMAGED)
        }
        val url = data.optString("u").trim().trimEnd('/')
        if (!url.startsWith("https://", ignoreCase = true) && !url.startsWith("http://", ignoreCase = true)) throw CodeError(DAMAGED)
        if (install) {
            val token = data.optString("t").trim()
            if (!TOKEN.matches(token)) throw CodeError(DAMAGED)
            return Code.Install(url, token)
        }
        val id = data.optString("i").trim()
        val key = data.optString("k").trim()
        if (!UUID.matches(id) || key.isEmpty()) throw CodeError(DAMAGED)
        return Code.Agent(url, id.lowercase(), key)
    }
}

/** Pure rules the inventory uses (unit-tested without a phone). */
object Rules {
    /** Days since the security patch level ("2026-10-05"), or null when it cannot be read. */
    fun patchAgeDays(securityPatch: String?, today: LocalDate): Long? = try {
        if (securityPatch.isNullOrBlank()) null else ChronoUnit.DAYS.between(LocalDate.parse(securityPatch.trim()), today).coerceAtLeast(0)
    } catch (e: DateTimeParseException) {
        null
    }

    val SU_PATHS = listOf(
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/su", "/su/bin/su",
        "/data/local/xbin/su", "/data/local/bin/su", "/system/app/Superuser.apk",
    )
    val ROOT_APPS = listOf("com.topjohnwu.magisk", "eu.chainfire.supersu", "com.koushikdutta.superuser", "com.noshufou.android.su")

    /** Signs that the phone is rooted: a build signed with test keys, an su binary, a root manager app. */
    fun rootSignals(buildTags: String?, fileExists: (String) -> Boolean, appInstalled: (String) -> Boolean): List<String> {
        val out = mutableListOf<String>()
        if (buildTags?.contains("test-keys") == true) out += "test-keys build"
        SU_PATHS.firstOrNull(fileExists)?.let { out += "su binary ($it)" }
        ROOT_APPS.firstOrNull(appInstalled)?.let { out += "root app ($it)" }
        return out
    }

    /** The phone's OS install id for the server: Android's per-app device id is 16 hex digits and the
     *  server takes 32 (lib/machineIdentity.ts), so a SHA-256 of it, cut to 32. The raw id never leaves. */
    fun osInstallId(androidId: String?): String? {
        if (androidId.isNullOrBlank()) return null
        val digest = MessageDigest.getInstance("SHA-256").digest("android:${androidId.trim().lowercase()}".toByteArray())
        return digest.joinToString("") { "%02x".format(it) }.substring(0, 32)
    }

    /** A tablet has a smallest screen width of 600 dp or more. */
    fun formFactor(smallestWidthDp: Int): String = if (smallestWidthDp >= 600) "tablet" else "phone"

    /** Whether an inventory is due: on, and the last one older than the interval (or a job asks). */
    fun inventoryDue(enabled: Boolean, lastAtMs: Long, intervalSeconds: Long, nowMs: Long, forced: Boolean): Boolean =
        enabled && (forced || lastAtMs <= 0 || nowMs - lastAtMs >= intervalSeconds * 1000)
}
