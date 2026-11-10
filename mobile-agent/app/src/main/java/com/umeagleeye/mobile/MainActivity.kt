package com.umeagleeye.mobile

import android.app.Activity
import android.content.Intent
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.text.InputType
import android.text.format.DateUtils
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.net.URL

/** The app's one screen: connect with a code from the dashboard, then what the agent last did, and
 *  what it sends. The work itself runs in AgentJobService every 15 minutes. */
class MainActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var detail: TextView
    private lateinit var codeBox: EditText
    private lateinit var connectButton: Button
    private lateinit var checkButton: Button
    private lateinit var disconnectButton: Button
    private lateinit var batteryButton: Button
    private val pad by lazy { (16 * resources.displayMetrics.density).toInt() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val column = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(pad, pad, pad, pad) }
        column.addView(text("EagleEye Agent", 22f, bold = true))
        column.addView(text("Reports this phone's security settings to your organisation's EagleEye dashboard.", 14f))
        status = text("", 16f, bold = true).also { it.setPadding(0, pad, 0, pad / 2); column.addView(it) }
        detail = text("", 14f).also { column.addView(it) }

        codeBox = EditText(this).apply {
            hint = "Paste the code from the dashboard (EE1… or EE2…)"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            minLines = 3
            gravity = Gravity.TOP
        }
        column.addView(codeBox)
        connectButton = button("Connect") { connect() }.also { column.addView(it) }
        checkButton = button("Check now") { checkNow() }.also { column.addView(it) }
        batteryButton = button("Allow background checks") { askBatteryExemption() }.also { column.addView(it) }
        disconnectButton = button("Disconnect") { disconnect() }.also { column.addView(it) }

        column.addView(text("What it sends", 16f, bold = true).also { it.setPadding(0, pad, 0, pad / 4) })
        column.addView(text(
            "• The phone's name, maker and model, Android version and security patch level\n" +
                "• Screen lock, storage encryption, signs of root, USB debugging\n" +
                "• Its address on the Wi-Fi it is on (not on mobile data)\n" +
                "• Installed apps and their versions, only if your administrator turns that on\n\n" +
                "Never: your accounts, messages, contacts, photos, files, location or browsing. " +
                "The app does not scan or listen to the network.", 14f))
        setContentView(ScrollView(this).apply { addView(column) })
    }

    override fun onResume() {
        super.onResume()
        AgentJobService.ensureScheduled(this)
        refresh()
    }

    /** Whether Android lets the 15-minute check run while the phone sleeps (battery optimisation off). */
    private fun unrestricted(): Boolean =
        getSystemService(PowerManager::class.java)?.isIgnoringBatteryOptimizations(packageName) == true

    /** Android's own prompt: "Let app always run in background?" (Settings as a fallback). */
    private fun askBatteryExemption() {
        val ask = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:$packageName"))
        runCatching { startActivity(ask) }.onFailure {
            runCatching { startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)) }
        }
    }

    private fun refresh() {
        val store = Store(this)
        val connected = store.connected
        codeBox.visibility = if (connected) View.GONE else View.VISIBLE
        connectButton.visibility = if (connected) View.GONE else View.VISIBLE
        checkButton.visibility = if (connected) View.VISIBLE else View.GONE
        disconnectButton.visibility = if (connected) View.VISIBLE else View.GONE
        batteryButton.visibility = if (connected && !unrestricted()) View.VISIBLE else View.GONE
        if (!connected) {
            status.text = "Not connected"
            detail.text = "On the dashboard: Agents > Install > Android > Register agent, then paste the code here."
            return
        }
        val host = runCatching { URL(store.apiUrl).host }.getOrDefault(store.apiUrl ?: "")
        status.text = if (store.lastHeartbeatOk) "Connected" else "Connected (last check failed)"
        detail.text = buildString {
            append("Server: $host\nAgent: ${store.agentId?.take(8)}…\n")
            append("Last check: ${ago(store.lastHeartbeatAt)}\n")
            append("Last inventory: ${ago(store.lastInventoryAt)}")
            append(if (store.inventoryOn) " (every ${store.inventoryInterval / 3600} h)" else " (switched off by your administrator)")
            append("\nInstalled apps: ${if (store.sendApps) "sent" else "not sent"}")
            append("\n\nBackground check: ${if (AgentJobService.isScheduled(this@MainActivity)) "every 15 minutes" else "not scheduled"}")
            append("\nLast background check: ${ago(store.lastBackgroundAt)}")
            append(if (unrestricted()) "\nBattery: unrestricted (checks run while the phone sleeps)"
                else "\nBattery: optimised (Android may hold the checks back while the phone sleeps)")
            store.lastMessage?.let { append("\n\n$it") }
        }
    }

    private fun ago(ms: Long) = if (ms <= 0) "never" else DateUtils.getRelativeTimeSpanString(ms).toString()

    private fun connect() {
        val code = codeBox.text.toString()
        busy("Connecting…")
        Thread {
            val message = try {
                val result = Agent.connect(applicationContext, code)
                AgentJobService.schedule(applicationContext)
                result
            } catch (e: CodeError) {
                Store(applicationContext).let { if (!it.connected) it.forget() }
                e.message ?: "The code could not be used."
            } catch (e: Exception) {
                "Could not connect: ${e.javaClass.simpleName} ${e.message ?: ""}"
            }
            runOnUiThread { done(message) }
        }.start()
    }

    private fun checkNow() {
        busy("Checking…")
        Thread {
            val message = runCatching { Agent.runOnce(applicationContext, forceInventory = true) }
                .getOrElse { "Check failed: ${it.javaClass.simpleName} ${it.message ?: ""}" }
            runOnUiThread { done(message) }
        }.start()
    }

    private fun disconnect() {
        Agent.disconnect(this)
        codeBox.setText("")
        refresh()
    }

    private fun busy(message: String) {
        status.text = message
        connectButton.isEnabled = false
        checkButton.isEnabled = false
    }

    private fun done(message: String) {
        connectButton.isEnabled = true
        checkButton.isEnabled = true
        refresh()
        if (!Store(this).connected) detail.text = message
    }

    private fun text(value: String, size: Float, bold: Boolean = false) = TextView(this).apply {
        text = value
        textSize = size
        if (bold) setTypeface(typeface, Typeface.BOLD)
    }

    private fun button(label: String, onClick: () -> Unit) = Button(this).apply {
        text = label
        setOnClickListener { onClick() }
    }
}
