# EagleEye phone agent (Android)

The EagleEye agent for Android phones and tablets (Android 8+). It reports the phone's own inventory
and security settings to the dashboard as an agent of kind `mobile`; it never scans or listens to the
network. Native Kotlin on the Android framework only: no AndroidX or third-party libraries in the app.

| | |
|---|---|
| Connect | Paste a connection code (`EE1.`, one phone) or an install code for phones (`EE2.`, many) |
| Runs | Every 15 minutes (JobScheduler, kept after a restart), and on "Check now" |
| Heartbeat | `POST /agents/:id/heartbeat` with `kind: mobile`; applies the managed settings (inventory on/off, interval, apps) and handles "Collect inventory" jobs (others are declined) |
| Inventory | `POST /agents/:id/inventory`, schema 1 like the computers' agents, `platform: android` |
| Key | The API key is encrypted with an AES key in the Android Keystore |

What the inventory holds: the phone's name, maker and model, memory and storage, Android version,
build and security patch level (`days_since_last_patch`), storage encryption, screen lock, signs of
root (test-keys build, an `su` binary, a root manager app), USB debugging and developer options, and
its Wi-Fi address and gateway. Installed apps (name, version, install date; system apps left out)
only when the dashboard's "Include software users installed for themselves" is on. Android hides the
real MAC from apps, so none is sent; the server's OS install id is a SHA-256 of Android's per-app
device id, cut to 32 hex digits. On mobile data no address is sent (a carrier's 10.x address would
look like a device on the company network), so the first report waits for Wi-Fi.

The server scores a phone by its own checks (workers/src/lib/endpointPosture.ts): storage encryption,
security patch level (warn after 90 days, fail after 180), screen lock, root and USB debugging.

## Build

Needs JDK 17 and the Android SDK (platform 35, build tools 35.0.0); `local.properties` points at it
(`sdk.dir=C:/Users/<you>/AppData/Local/Android/Sdk`, forward slashes).

```powershell
cd mobile-agent
$env:JAVA_HOME = "C:\Program Files\Java\jdk-17"
.\gradlew.bat assembleDebug testDebugUnitTest
copy app\build\outputs\apk\debug\app-debug.apk dist\EagleEyeMobile-<version>.apk
```

The dashboard offers the newest upload of `agent-installer/EagleEyeMobile-<version>.apk` in R2
(Agents > Install > Android). The debug build is signed with the build machine's debug key, which is
fine for testers sideloading it; a release for others needs a release signing key.
