## Android Security Toolkit — Module Technical Reference

> **Purpose:** This document explains the technical logic of each module within the Android Security Toolkit application, intended for academic research and security lab reporting.

---

## Architecture Overview

```
com.sectoolkit/
├── model/          # Pure data classes (AppInfo, ExportedComponent, IntentExtra, ClipboardEntry)
├── recon/          # Module 1 — ExportedComponentScanner
├── intent/         # Module 2 — IntentDispatcher
├── provider/       # Module 3 — ContentProviderAuditor
├── clipboard/      # Module 4 — ClipboardMonitorService
└── ui/             # Fragments, Adapters, MainActivity

```

**Design Pattern:** Utilizes the **Singleton** pattern for all core logic classes to ensure a single instance per module throughout the application lifecycle. The UI layer is strictly decoupled from business logic following the **Separation of Concerns** principle.

---

## Module 1 — Attack Surface Reconnaissance

### Class: `ExportedComponentScanner`

#### Technical Objective

To identify the **Attack Surface** of an Android application by enumerating all components exported to the external environment.

#### Core Android APIs

| API | Purpose |
| --- | --- |
| `PackageManager.getInstalledPackages()` | Retrieves a list of all installed applications. |
| `PackageManager.GET_ACTIVITIES` | Flag to retrieve Activity information. |
| `PackageManager.GET_SERVICES` | Flag to retrieve Service information. |
| `PackageManager.GET_RECEIVERS` | Flag to retrieve BroadcastReceiver information. |
| `PackageManager.GET_PROVIDERS` | Flag to retrieve ContentProvider information. |
| `ActivityInfo.exported` | Boolean field determining if a component is exported. |

#### Operational Logic

```
getAllInstalledApps()
  └─► PackageManager.getInstalledPackages(GET_ACTIVITIES | GET_SERVICES | GET_RECEIVERS | GET_PROVIDERS)
        └─► Iterate through PackageInfo[] array
              └─► countExportedComponents(pkg)
                    ├─► pkg.activities[] → check ActivityInfo.exported
                    ├─► pkg.services[]   → check ServiceInfo.exported
                    ├─► pkg.receivers[]  → check ActivityInfo.exported
                    └─► pkg.providers[]  → check ProviderInfo.exported

getExportedComponents(packageName)
  └─► PackageManager.getPackageInfo(packageName, flags)
        └─► Iterate through component arrays
              └─► If info.exported == true:
                    ├─► Record class name
                    ├─► Record component type (ACTIVITY/SERVICE/RECEIVER/PROVIDER)
                    └─► Check info.permission != null → classify as PROTECTED / NO PERMISSION

```

#### Security Implications

* **Components with `exported=true` and NO `permission**`: This is a critical vulnerability. Any application on the device can launch this component without authentication.
* **Real-world Attack Scenario**: A `LoginActivity` is exported without permissions, allowing an attacker to bypass the login screen by directly calling the Activity that follows the authentication stage.
* **`QUERY_ALL_PACKAGES` Permission**: Mandatory from Android 11 (API 30) onwards to query information about all packages. Without this, the system returns a restricted list.

---

## Module 2 — Intent Exploitation Lab

### Class: `IntentDispatcher`

#### Technical Objective

Simulates **Intent Spoofing** — sending manually crafted Intents to a specific component, bypassing Android's standard Intent Filter resolution mechanism.

#### Core Android APIs

| API | Purpose |
| --- | --- |
| `ComponentName(packageName, className)` | Defines an exact target, bypassing Intent resolution. |
| `Intent.setComponent()` | Applies the ComponentName to the Intent. |
| `Context.startActivity()` | Dispatches the Intent to an Activity. |
| `Context.startService()` | Dispatches the Intent to a Service. |
| `Context.sendBroadcast()` | Broadcasts the Intent to Receivers. |
| `Intent.putExtra()` | Attaches data to the Intent. |

#### Operational Logic

```
dispatch(packageName, className, action, extras, mode)
  └─► buildIntent()
        ├─► If packageName + className != null:
        │     └─► intent.setComponent(new ComponentName(pkg, cls))
        │           [Explicit Intent — bypasses Intent Filter]
        ├─► If only packageName is present:
        │     └─► intent.setPackage(pkg)
        ├─► If action is present:
        │     └─► intent.setAction(action)
        └─► For each IntentExtra:
              └─► applyExtra(intent, extra)
                    └─► Switch(extra.type):
                          STRING  → putExtra(key, String)
                          INT     → putExtra(key, Integer.parseInt(value))
                          BOOLEAN → putExtra(key, Boolean.parseBoolean(value))
                          LONG    → putExtra(key, Long.parseLong(value))
                          FLOAT   → putExtra(key, Float.parseFloat(value))

  └─► Switch(mode):
        ACTIVITY  → context.startActivity(intent)
        SERVICE   → context.startService(intent)
        BROADCAST → context.sendBroadcast(intent)

```

#### Security Implications

**The Danger of `ComponentName**`
Implicit Intents (Intents with only an action) go through Android's Intent Resolution to find a matching component based on `<intent-filter>`. However, using `ComponentName` creates an **Explicit Intent**:

1. Android completely bypasses the Intent Resolution step.
2. The Intent is sent directly to the specified component.
3. The target component does not even need to declare a matching `<intent-filter>`.

**Typical Attack Scenario:**

* A target app has a `com.bank.app.DashboardActivity` with `exported=true` but no `permission`.
* An attacker uses this tool to send an Explicit Intent to `DashboardActivity` with an extra `isLoggedIn=true`.
* **Result:** The login screen is completely bypassed.

---

## Module 3 — Content Provider Auditor

### Class: `ContentProviderAuditor`

#### Technical Objective

Exploits **Insecure Content Providers** — retrieving raw data from another application's SQLite database via `ContentResolver` without requiring special permissions if the Provider is unprotected.

#### Core Android APIs

| API | Purpose |
| --- | --- |
| `ContentResolver.query(uri, null, null, null, null)` | Queries all rows and columns from a URI. |
| `Uri.parse(uriString)` | Parses a string into an Android Uri object. |
| `Cursor.getColumnNames()` | Retrieves the list of column names. |
| `Cursor.moveToNext()` | Iterates through each row in the result set. |
| `Cursor.getString(columnIndex)` | Reads the value of a specific data cell. |

#### Operational Logic

```
query(uriString)
  ├─► Validate: uriString is not null/empty
  ├─► Uri.parse(uriString) → Uri object
  └─► ContentResolver.query(uri, null, null, null, null)
        │   [null projection = SELECT *]
        │   [null selection = empty WHERE clause]
        │   [null sortOrder = no ORDER BY]
        └─► Cursor result
              ├─► If cursor == null → Provider does not exist or access denied
              ├─► cursor.getColumnNames() → List<String> columns
              └─► while(cursor.moveToNext()):
                    └─► For each column:
                          cursor.getString(i) → value
                          Add to Map<String, String> row
              └─► Return QueryResult(columns, rows)

Exception Handling:
  SecurityException       → Provider requires permission, access denied.
  IllegalArgumentException → Invalid URI format.
  Exception               → Unknown error.

```

#### Security Implications

**Content Provider URI Structure:**

```
content://[authority]/[path]/[id]
  │              │        │     └─ Specific Record ID (Optional)
  │              │        └─ Path to the data table
  │              └─ Package or authority string of the provider
  └─ Mandatory Scheme

```

**Real-world Dangerous URI Examples:**

* `content://com.android.contacts/contacts` → Contact list
* `content://sms` → SMS messages
* `content://com.vulnerable.app/users` → Vulnerable app's user database
* `content://com.vulnerable.app/credentials` → Exposed credentials

**Conditions for a Successful Attack:**

* The Provider has `android:exported="true"` in the Manifest.
* The Provider lacks `android:readPermission` or `android:writePermission`.
* The Provider lacks a general `android:permission`.

Under these conditions, any app on the same device can read the victim app's entire SQLite database.

---

## Module 4 — Data Leakage Monitor (Clipboard)

### Class: `ClipboardMonitorService`

#### Technical Objective

Implements the **Sensitive Data Exposure via Clipboard** technique — registering a listener for clipboard events to log any text copied by the user, including passwords, OTP codes, and credit card numbers.

#### Core Android APIs

| API | Purpose |
| --- | --- |
| `ClipboardManager` | System service managing the clipboard. |
| `ClipboardManager.addPrimaryClipChangedListener()` | Registers callback for clipboard changes. |
| `ClipboardManager.getPrimaryClip()` | Retrieves the current clipboard content. |
| `ClipData.Item.getText()` | Reads text from a clipboard item. |
| `Service.startForeground()` | Runs the service in the foreground with a notification. |
| `NotificationChannel` | Required notification channel for Android 8+. |

#### Operational Logic

```
ClipboardMonitorService extends Service
  │
  onCreate()
    ├─► getSystemService(CLIPBOARD_SERVICE) → ClipboardManager
    ├─► clipboardManager.addPrimaryClipChangedListener(clipListener)
    └─► startForeground(NOTIFICATION_ID, buildNotification())
          [Mandatory to prevent the OS from killing the service]

  OnPrimaryClipChangedListener.onPrimaryClipChanged()  ← [TRIGGER]
    ├─► clipboardManager.hasPrimaryClip() → check for data
    ├─► getPrimaryClip().getItemAt(0) → get the first item
    ├─► item.getText().toString() → text string
    ├─► Create ClipboardEntry(text, System.currentTimeMillis())
    ├─► capturedEntries.add(0, entry) → add to top of list (newest first)
    └─► eventListener.onNewClipboardEntry(entry) → notify UI

  onDestroy()
    └─► clipboardManager.removePrimaryClipChangedListener(clipListener)
          [Cleanup listener to prevent memory leaks]

```

#### Security Implications

**Why is this a serious vulnerability?**
Prior to Android 12 (API 31), any application running in the background could read the clipboard without special permissions. This was a common attack vector for:

| Sensitive Data Type | Exposure Scenario |
| --- | --- |
| Passwords | Copied from a password manager |
| OTP / 2FA Codes | Copied from SMS or authenticator apps |
| Credit Card Numbers | Copied during payment information entry |
| Private Keys / Seeds | Copied while setting up crypto wallets |
| Auth Tokens | Copied API keys or bearer tokens |

**Defense Measures (for Developers):**

* Use `ClipboardManager.clearPrimaryClip()` immediately after pasting.
* Implement custom keyboards with `TYPE_TEXT_FLAG_NO_SUGGESTIONS`.
* Use `AutofillService` instead of the clipboard for sensitive data.
* Implement time-based clipboard clearing.

**Changes since Android 12:**
Starting with Android 12 (API 31), a system toast notification is displayed whenever a background app reads the clipboard. This mitigates but does not fully eliminate the risk.

---

## Technical Summary Table

| Module | Core Class | Primary Android API | Vulnerability Type | Risk Level |
| --- | --- | --- | --- | --- |
| Recon | `ExportedComponentScanner` | `PackageManager` | Exposed Attack Surface |
| Intent Lab | `IntentDispatcher` | `ComponentName`, `Intent` | Intent Spoofing |
| Provider | `ContentProviderAuditor` | `ContentResolver.query()` | Insecure Data Storage | 
| Clipboard | `ClipboardMonitorService` | `ClipboardManager` | Sensitive Data Exposure | 

---

## Lab Usage Instructions

### Module 1 — Recon

1. Open the **Recon** tab.
2. Wait for the app list to load (Yellow chips indicate apps with exported components).
3. Tap an app to analyze.
4. Review components: Red "NO PERMISSION" chips indicate potential targets.

### Module 2 — Intent Lab

1. Open the **Intent Lab** tab.
2. Enter the Package Name from Recon (e.g., `com.target.app`).
3. Enter the Class Name of the discovered component (e.g., `com.target.app.AdminActivity`).
4. Select mode: **Activity** / **Service** / **Broadcast**.
5. Add Extras if necessary (e.g., `isAdmin=true`).
6. Press **DISPATCH INTENT**.

### Module 3 — Provider Auditor

1. Open the **Provider** tab.
2. Enter the provider URI from Recon (e.g., `content://com.target.app.provider/users`).
3. Press **QUERY**.
4. Results are displayed in a table showing all rows and columns.

### Module 4 — Clipboard Monitor

1. Open the **Clipboard** tab.
2. Toggle **Monitor Status** to ON.
3. Copy any text on the device.
4. Return to the app to view captured data with timestamps.

---

## Disclaimer

> This tool was developed **strictly for educational and security research purposes**. Using this tool to attack systems or applications without explicit authorization is **illegal**. Only use this tool on your own devices/apps or within authorized lab environments.
