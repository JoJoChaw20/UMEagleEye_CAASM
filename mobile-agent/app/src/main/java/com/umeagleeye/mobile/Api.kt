package com.umeagleeye.mobile

import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/** The EagleEye API, as the computers' agent uses it (agent-gui/eagleeye/api.py). */
class Api(private val baseUrl: String, private val apiKey: String?) {
    data class Response(val code: Int, val body: String) {
        val ok get() = code in 200..299
        fun json(): JSONObject = runCatching { JSONObject(body) }.getOrDefault(JSONObject())
        /** The server's own words ("detail"), else the status. */
        fun problem(): String = json().optString("detail").ifBlank { "HTTP $code" }
    }

    @Throws(IOException::class)
    fun post(path: String, body: JSONObject, timeoutMs: Int = 30_000): Response {
        val conn = URL(baseUrl.trimEnd('/') + path).openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.connectTimeout = 15_000
            conn.readTimeout = timeoutMs
            conn.instanceFollowRedirects = false            // never re-send the key elsewhere
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("User-Agent", "EagleEyeMobile/${Agent.VERSION}")
            apiKey?.let { conn.setRequestProperty("Authorization", "Bearer $it") }
            conn.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
            val code = conn.responseCode
            val stream = if (code >= 400) conn.errorStream else conn.inputStream
            val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
            return Response(code, text)
        } finally {
            conn.disconnect()
        }
    }
}
