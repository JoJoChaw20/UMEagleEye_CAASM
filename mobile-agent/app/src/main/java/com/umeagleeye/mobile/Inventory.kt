package com.umeagleeye.mobile

import android.app.ActivityManager
import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Environment
import android.os.StatFs
import android.os.SystemClock
import android.provider.Settings
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.Inet4Address
import java.time.Instant
import java.time.ZoneOffset

/** This phone's endpoint inventory: the same document (schema 1) as the computers' agents send
 *  (agent-gui/eagleeye/collectors), so the server binds, scores and shows it the same way
 *  (workers/src/lib/endpointPosture.ts has the phone's own checks). Only facts Android lets an
 *  ordinary app read; nothing personal: no accounts, messages, contacts, photos or location. */
object Inventory {
    /** This phone's address on the Wi-Fi it is on, or null (mobile data: a carrier's address
     *  would look like a device on the company's own 10.x network). */
    fun wifi(context: Context): Wifi? {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return null
        val network = cm.activeNetwork ?: return null
        val caps = cm.getNetworkCapabilities(network) ?: return null
        if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) && !caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) return null
        val link = cm.getLinkProperties(network) ?: return null
        val v4 = link.linkAddresses.firstOrNull { it.address is Inet4Address } ?: return null
        val gateway = link.routes.firstOrNull { it.isDefaultRoute && it.gateway is Inet4Address }?.gateway?.hostAddress
        return Wifi(link.interfaceName ?: "wlan0", v4.address.hostAddress ?: return null, v4.prefixLength, gateway,
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) "Wi-Fi" else "Ethernet")
    }

    data class Wifi(val iface: String, val ip: String, val prefix: Int, val gateway: String?, val kind: String)

    fun deviceName(context: Context): String =
        Settings.Global.getString(context.contentResolver, Settings.Global.DEVICE_NAME)?.takeIf { it.isNotBlank() }
            ?: "${Build.MANUFACTURER.replaceFirstChar { it.uppercase() }} ${Build.MODEL}"

    fun collect(context: Context, includeApps: Boolean, nowMs: Long = System.currentTimeMillis()): JSONObject {
        val errors = JSONArray()
        fun <T> section(name: String, default: T, block: () -> T): T = try {
            block()
        } catch (e: Exception) {                         // one unreadable fact never loses the rest
            errors.put("$name: ${e.javaClass.simpleName}: ${e.message}".take(500))
            default
        }
        val now = Instant.ofEpochMilli(nowMs)
        val today = now.atZone(ZoneOffset.UTC).toLocalDate()
        val cr = context.contentResolver
        val pm = context.packageManager

        val identity = JSONObject()
            .put("hostname", deviceName(context).take(255))
            .put("dns_hostname", JSONObject.NULL).put("domain", JSONObject.NULL).put("part_of_domain", false)
            .put("workgroup", JSONObject.NULL)
            .put("machine_id", Rules.osInstallId(Settings.Secure.getString(cr, Settings.Secure.ANDROID_ID)) ?: JSONObject.NULL)
            .put("smbios_uuid", JSONObject.NULL).put("serial_number", JSONObject.NULL)

        val hardware = section("hardware", JSONObject()) {
            val mem = ActivityManager.MemoryInfo().also { context.getSystemService(ActivityManager::class.java)?.getMemoryInfo(it) }
            val soc = if (Build.VERSION.SDK_INT >= 31) "${Build.SOC_MANUFACTURER} ${Build.SOC_MODEL}".trim() else Build.HARDWARE
            val cores = Runtime.getRuntime().availableProcessors()
            JSONObject()
                .put("manufacturer", Build.MANUFACTURER.replaceFirstChar { it.uppercase() })
                .put("model", Build.MODEL)
                .put("form_factor", Rules.formFactor(context.resources.configuration.smallestScreenWidthDp))
                .put("memory_bytes", mem.totalMem.takeIf { it > 0 } ?: JSONObject.NULL)
                .put("cpus", JSONArray().put(JSONObject().put("name", soc).put("cores", cores).put("threads", cores)))
                .put("disks", JSONArray().put(JSONObject().put("model", "Internal storage")
                    .put("size_bytes", StatFs(Environment.getDataDirectory().path).totalBytes).put("media", "Flash")))
                .put("volumes", JSONArray()).put("bios", JSONObject.NULL)
        }

        val os = JSONObject()
            .put("name", "Android ${Build.VERSION.RELEASE}")
            .put("version", Build.VERSION.RELEASE).put("build", Build.DISPLAY.take(32))
            .put("display_version", Build.VERSION.RELEASE).put("edition", JSONObject.NULL)
            .put("architecture", Build.SUPPORTED_ABIS.firstOrNull() ?: JSONObject.NULL)
            .put("role", "mobile")
            .put("install_date", JSONObject.NULL)
            .put("last_boot", Instant.ofEpochMilli(nowMs - SystemClock.elapsedRealtime()).toString())

        val patch = Build.VERSION.SECURITY_PATCH
        val age = Rules.patchAgeDays(patch, today)
        val patches = JSONObject()
            .put("hotfix_count", if (age != null) 1 else 0)
            .put("last_patch_id", if (patch.isNullOrBlank()) JSONObject.NULL else "Android security patch $patch")
            .put("last_patch_date", if (age != null) "${patch}T00:00:00+00:00" else JSONObject.NULL)
            .put("days_since_last_patch", age ?: JSONObject.NULL)
            .put("pending_reboot", JSONObject.NULL)
            .put("hotfixes", JSONArray())

        val security = section("security", JSONObject()) {
            val keyguard = context.getSystemService(KeyguardManager::class.java)
            val dpm = context.getSystemService(DevicePolicyManager::class.java)
            val encryption = when (dpm?.storageEncryptionStatus) {
                DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE, DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER,
                DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY -> "on"
                null -> null
                else -> "off"
            }
            val signals = Rules.rootSignals(Build.TAGS, { File(it).exists() }, { pkg -> installed(pm, pkg) })
            JSONObject()
                .put("firewall", JSONArray()).put("firewall_all_enabled", JSONObject.NULL)
                .put("antivirus", JSONArray())
                .put("disk_encryption", if (encryption == null) JSONObject.NULL
                    else JSONArray().put(JSONObject().put("volume", "/data").put("protection", encryption)))
                .put("tpm", JSONObject.NULL).put("secure_boot", JSONObject.NULL).put("uac_enabled", JSONObject.NULL)
                .put("rdp_enabled", JSONObject.NULL).put("smb1_enabled", JSONObject.NULL)
                .put("local_admins", JSONArray()).put("local_admin_count", JSONObject.NULL)
                .put("screen_lock", keyguard?.isDeviceSecure ?: JSONObject.NULL)
                .put("rooted", signals.isNotEmpty())
                .put("root_signals", JSONArray(signals))
                .put("usb_debugging", Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) == 1)
                .put("developer_options", Settings.Global.getInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1)
        }

        val wifi = section("network", null) { wifi(context) }
        val interfaces = JSONArray()
        if (wifi != null) {
            // Android hides the real MAC from apps (and shows a per-network random one to the Wi-Fi)
            interfaces.put(JSONObject().put("name", wifi.iface).put("description", wifi.kind).put("mac", JSONObject.NULL)
                .put("status", "Up").put("virtual", false).put("physical", true).put("speed_bps", JSONObject.NULL)
                .put("ipv4", JSONArray().put(wifi.ip)).put("ipv6", JSONArray()))
        }
        val network = JSONObject().put("primary_ip", wifi?.ip ?: JSONObject.NULL)
            .put("interfaces", interfaces).put("listening", JSONArray())

        val software = if (includeApps) section("software", JSONArray()) { apps(pm) } else JSONArray()
        return JSONObject()
            .put("schema", 1).put("platform", "android")
            .put("collected_at", now.toString()).put("agent_version", Agent.VERSION)
            .put("is_admin", false)
            .put("identity", identity).put("hardware", hardware).put("os", os).put("patches", patches)
            .put("security", security).put("network", network).put("software", software)
            .put("unavailable", JSONArray().put("hardware_uuid").put("mac"))
            .put("privacy", JSONObject().put("user_software", includeApps).put("admin_names", false))
            .put("errors", errors)
    }

    private fun installed(pm: PackageManager, pkg: String): Boolean = try {
        pm.getPackageInfo(pkg, 0)
        true
    } catch (e: PackageManager.NameNotFoundException) {
        false
    }

    /** The apps someone installed (and updated system apps): name, version, install date. */
    @Suppress("DEPRECATION")
    private fun apps(pm: PackageManager): JSONArray {
        val list = if (Build.VERSION.SDK_INT >= 33) pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0))
            else pm.getInstalledPackages(0)
        val out = JSONArray()
        for (p in list.sortedBy { it.packageName }) {
            val app = p.applicationInfo ?: continue
            val system = app.flags and ApplicationInfo.FLAG_SYSTEM != 0
            val updated = app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
            if (system && !updated) continue
            val name = pm.getApplicationLabel(app).toString().ifBlank { p.packageName }
            out.put(JSONObject().put("name", name.take(255)).put("version", (p.versionName ?: "").take(100))
                .put("publisher", JSONObject.NULL)
                .put("install_date", Instant.ofEpochMilli(p.firstInstallTime).atZone(ZoneOffset.UTC).toLocalDate().toString())
                .put("scope", "user").put("arch", JSONObject.NULL))
            if (out.length() >= 5000) break
        }
        return out
    }
}
