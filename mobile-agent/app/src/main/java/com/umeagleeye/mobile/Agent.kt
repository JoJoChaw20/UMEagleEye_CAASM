package com.umeagleeye.mobile

import android.content.Context
import android.os.Build
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException

/** One round of the phone agent (every 15 minutes, and when "Check now" is pressed): a heartbeat
 *  that brings the administrator's settings and any jobs, then the inventory when it is due or a
 *  job asks for it. A phone only reports itself: it never scans or listens to the network. */
object Agent {
    const val VERSION = "0.1.0"
    const val KIND = "mobile"

    /** Connect with a code from the dashboard. Returns a message to show. */
    fun connect(context: Context, text: String): String {
        val store = Store(context)
        when (val code = Codes.parse(text)) {
            is Code.Agent -> {
                store.apiUrl = code.apiUrl; store.agentId = code.agentId; store.apiKey = code.apiKey
            }
            is Code.Install -> {
                val r = Api(code.apiUrl, null).post("/enrolment/enrol",
                    JSONObject().put("token", code.token).put("name", Inventory.deviceName(context).take(255)).put("kind", KIND))
                if (!r.ok) throw CodeError("The server refused the install code: ${r.problem()}")
                val body = r.json()
                val id = body.optString("agent_id")
                val key = body.optString("api_key")
                if (id.isBlank() || key.isBlank()) throw CodeError("The server's answer was incomplete. Try again.")
                store.apiUrl = code.apiUrl; store.agentId = id; store.apiKey = key
            }
        }
        store.lastInventoryAt = 0                      // the first round sends the inventory at once
        return runOnce(context, forceInventory = true)
    }

    @Synchronized
    fun runOnce(context: Context, forceInventory: Boolean = false): String {
        val store = Store(context)
        val url = store.apiUrl
        val id = store.agentId
        val key = store.apiKey
        if (url == null || id == null || key == null) return "Not connected"
        val api = Api(url, key)
        val now = System.currentTimeMillis()
        val wifi = runCatching { Inventory.wifi(context) }.getOrNull()

        // 1. Heartbeat: this phone's own settings and what it can do; back come the managed settings and jobs
        val beat = JSONObject()
            .put("version", VERSION).put("kind", KIND).put("want_jobs", true)
            .put("settings", JSONObject().put("inventory", true).put("inventory_interval", Store.DEFAULT_INVENTORY_INTERVAL)
                .put("inventory_user_software", false))
            .put("capabilities", JSONObject().put("os", "android").put("sdk", Build.VERSION.SDK_INT).put("admin", false))
        wifi?.ip?.let { beat.put("gateway_ip", it) }
        wifi?.gateway?.let { beat.put("default_gateway", it) }
        store.policyVersion?.let { beat.put("policy_version", it) }
        val reply = try {
            api.post("/agents/$id/heartbeat", beat, 20_000)
        } catch (e: IOException) {
            store.lastHeartbeatOk = false
            return remember(store, "Could not reach the EagleEye server (${e.javaClass.simpleName}). It tries again in 15 minutes.")
        }
        store.lastHeartbeatAt = now
        store.lastHeartbeatOk = reply.ok
        if (reply.code == 401 || reply.code == 404) {
            return remember(store, "The server no longer knows this phone (${reply.problem()}). Disconnect and connect again with a new code.")
        }
        if (!reply.ok) return remember(store, "Heartbeat refused: ${reply.problem()}")
        val body = reply.json()
        val sentVersion = store.policyVersion
        body.optJSONObject("policy")?.let { applyPolicy(store, it) }
        // New settings: say at once that they are applied (else the dashboard shows "applying…" until the next round)
        if (store.policyVersion != null && store.policyVersion != sentVersion) {
            runCatching { api.post("/agents/$id/heartbeat", beat.put("policy_version", store.policyVersion).put("want_jobs", false), 20_000) }
        }

        // 2. Jobs from the dashboard: "Collect inventory" is the only one a phone does
        var force = forceInventory
        val jobs = body.optJSONArray("scans") ?: JSONArray()
        for (i in 0 until jobs.length()) {
            val job = jobs.optJSONObject(i) ?: continue
            val scanId = job.optString("scan_id").ifBlank { job.optString("scanId") }
            val type = job.optString("scan_type").ifBlank { job.optString("scanType") }
            if (scanId.isBlank()) continue
            if (type == "inventory" && store.inventoryOn) {
                runCatching { api.post("/scans/$scanId/start", JSONObject(), 15_000) }
                force = true                          // the upload completes the job
            } else {
                val reason = if (type == "inventory") "Inventory is switched off for this phone."
                    else "A phone agent only reports its own inventory; it does not run $type jobs."
                runCatching { api.post("/scans/fail", JSONObject().put("agent_id", id).put("scan_id", scanId).put("reason", reason), 15_000) }
            }
        }

        // 3. Inventory, when due
        if (!Rules.inventoryDue(store.inventoryOn, store.lastInventoryAt, store.inventoryInterval, now, force)) {
            return remember(store, "Connected")
        }
        val inventory = Inventory.collect(context, includeApps = store.sendApps, nowMs = now)
        val sent = try {
            api.post("/agents/$id/inventory", inventory, 60_000)
        } catch (e: IOException) {
            return remember(store, "Could not send the inventory (${e.javaClass.simpleName}). It tries again in 15 minutes.")
        }
        if (!sent.ok) {
            val hint = if (wifi == null) " Connect to the Wi-Fi of your organisation for the first inventory." else ""
            return remember(store, "The server refused the inventory: ${sent.problem()}.$hint")
        }
        store.lastInventoryAt = now
        return remember(store, "Connected; inventory sent")
    }

    /** The settings the administrator manages for this phone (all of its kind's settings). */
    private fun applyPolicy(store: Store, policy: JSONObject) {
        val managed = policy.optJSONObject("managed") ?: return
        if (managed.has("inventory")) store.inventoryOn = managed.optBoolean("inventory", true)
        if (managed.has("inventory_interval")) store.inventoryInterval = managed.optLong("inventory_interval", Store.DEFAULT_INVENTORY_INTERVAL)
        if (managed.has("inventory_user_software")) store.sendApps = managed.optBoolean("inventory_user_software", false)
        policy.optString("version").takeIf { it.isNotBlank() }?.let { store.policyVersion = it }
    }

    private fun remember(store: Store, message: String): String {
        store.lastMessage = message
        return message
    }

    fun disconnect(context: Context) {
        AgentJobService.cancel(context)
        Store(context).forget()
    }
}
