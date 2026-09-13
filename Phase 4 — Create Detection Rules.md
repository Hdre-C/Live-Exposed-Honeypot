# Phase 4 — Create Detection Rules

In this phase, I created **Microsoft Sentinel Analytics Rules** to detect successful logins before exposing the honeypot to the internet.

The VM is still locked down during this phase so the detections can be tested against a clean baseline.

---

## 1. Successful VM Login Detection

The first detection monitors successful logins to the honeypot using `DeviceLogonEvents`.

```kusto
let MyDevice = "corp-na02-main";

DeviceLogonEvents
| where DeviceName == MyDevice
| where AccountName in~ ("administrator", "guest")
| where ActionType == "LogonSuccess"
| project TimeGenerated,
          RemoteIP,
          AccountName,
          DeviceName,
          ActionType,
          LogonType
| order by TimeGenerated desc
```

This detection will alert when the `administrator` or `guest` account successfully authenticates to the VM.

> 📸 **IMAGE 1 — VM Login Detection**
>
> Take a screenshot of the query inside **Microsoft Sentinel / Advanced Hunting**.
>
> Make sure the following are visible:
>
> - `DeviceLogonEvents`
> - `corp-na02-main`
> - `administrator` / `guest`
> - `LogonSuccess`

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="Successful VM Login Detection">
</p>

---

## 2. Successful MySQL Login Detection

The second detection monitors `MySQLAudit_CL` for successful authentication to the MySQL server.

The MySQL general log stores authentication events inside `RawData`, so the query parses the log into useful fields.

```kusto
let MyDevice = "corp-na02-main";

let FailedConnections =
MySQLAudit_CL
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| where RawData has "Access denied"
| extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
| distinct ConnectionId;

MySQLAudit_CL
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| where RawData has "Connect"
| extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
| extend ActionType =
    case(
        RawData has "Access denied", "LogonFailure",
        ConnectionId in (FailedConnections), "Ignore",
        "LogonSuccess"
    )
| where ActionType == "LogonSuccess"
| extend Username =
    replace_string(
        tostring(split(tostring(split(RawData, "@")[0]), " ")[-1]),
        "'",
        ""
    )
| extend IpAddress =
    replace_string(
        tostring(split(split(RawData, "@")[1], " ")[0]),
        "'",
        ""
    )
| project TimeGenerated,
          DeviceName,
          Username,
          IpAddress,
          ActionType,
          RawData
| order by TimeGenerated desc
```

This allows successful MySQL authentication to be separated from failed login attempts.

> 📸 **IMAGE 2 — MySQL Login Detection**
>
> Run the query and take a screenshot showing:
>
> - `MySQLAudit_CL`
> - `DeviceName`
> - `Username`
> - `IpAddress`
> - `ActionType`
>
> It is normal if there are no suspicious successful logins yet because the honeypot has not been exposed.

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="Successful MySQL Login Detection">
</p>

---

## 3. Create Sentinel Analytics Rules

Both queries were then configured as **Microsoft Sentinel Analytics Rules**.

The rules monitor for:

- Successful `administrator` or `guest` VM logins
- Successful MySQL authentication

The rules were enabled **before Phase 5** so they would already be active when the honeypot became publicly accessible.

> 📸 **IMAGE 3 — Sentinel Analytics Rules**
>
> Take a screenshot of the **Analytics Rules** page showing both detection rules enabled.
>
> Try to show:
>
> - VM successful login rule
> - MySQL successful login rule
> - Rule status = **Enabled**

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="Sentinel Analytics Rules">
</p>

---

## 4. Verify the Clean Baseline

Before exposure, I confirmed the detection rules were active and that there were no unexpected successful logins.

This creates a **clean baseline** before real attacker traffic is introduced.

```text
Clean Environment
       ↓
Logging Enabled
       ↓
Detection Rules Enabled
       ↓
Phase 5 — Expose Honeypot
```

---

## Phase 4 Complete

At the end of Phase 4:

- VM successful-login detection is enabled
- MySQL successful-login detection is enabled
- Sentinel Analytics Rules are active
- The environment has a clean pre-exposure baseline
- The honeypot is ready for **Phase 5 — Weaken & Expose**
