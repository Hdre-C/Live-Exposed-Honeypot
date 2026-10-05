# Phase 7 — Analyze the Breach

In Phase 7, I analyzed activity captured after the honeypot was exposed.

The investigation focused on:

- Successful VM logins
- Process activity
- Network connections
- File and registry activity
- MySQL activity
- Outbound network traffic

---

## 1. Investigate Successful VM Authentication

I reviewed successful logins to `corp-na02-main`.

```kusto
DeviceLogonEvents
| where DeviceName == "corp-na02-main"
| where RemoteIP == "80.94.95.43"
| where ActionType == "LogonSuccess"
| project TimeGenerated,
          RemoteIP,
          AccountName,
          DeviceName,
          ActionType,
          LogonType
| order by TimeGenerated asc
```

A successful remote interactive login occurred on **August 20, 2026 at 1:34:54 PM**.

- **Source IP:** `80.94.95.43`
- **Account:** `administrator`
- **Device:** `corp-na02-main`
- **Result:** `LogonSuccess`
- **Logon Type:** `RemoteInteractive`

<p align="center">
  <img src="https://imgur.com/V9Y4O3i.png" width="1200" alt="Successful RemoteInteractive Login">
</p>

---

## 2. Investigate Process Activity

After the successful login, I reviewed processes executed under the `administrator` account.

### RDP Session Initialization

```kusto
DeviceProcessEvents
| where DeviceName == "corp-na02-main"
| where AccountName == "administrator"
| where FileName in~ ("rdpclip.exe", "userinit.exe", "explorer.exe")
| project TimeGenerated,
          AccountName,
          DeviceName,
          FileName,
          ProcessCommandLine,
          InitiatingProcessCommandLine
| order by TimeGenerated asc
```

The following processes appeared immediately after the login:

- **1:34:57 PM** — `rdpclip.exe`
- **1:34:59 PM** — `userinit.exe`
- **1:34:59 PM** — `explorer.exe`

These events show the interactive Windows session being established.

<p align="center">
  <img src="https://imgur.com/wiD0BlP.png" width="1200" alt="RDP Session Initialization">
</p>

### Interactive Activity

```kusto
DeviceProcessEvents
| where DeviceName == "corp-na02-main"
| where AccountName == "administrator"
| where TimeGenerated between (
    datetime(2026-08-20 13:36:25) ..
    datetime(2026-08-20 13:36:35)
)
| where FileName =~ "Taskmgr.exe"
| project TimeGenerated,
          AccountName,
          DeviceName,
          FileName,
          ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by TimeGenerated asc
```

At **1:36:30 PM**, `Taskmgr.exe` was launched from `explorer.exe`.

This was the first clear user-driven activity observed after the remote session began.

<p align="center">
  <img src="https://imgur.com/XbasuHc.png" width="1200" alt="Task Manager Activity">
</p>

---

## 3. Investigate Network Activity

I reviewed network connections associated with the compromised session.

```kusto
DeviceNetworkEvents
| where DeviceName == "corp-na02-main"
| where TimeGenerated between (
    datetime(2026-08-20 13:35:15) ..
    datetime(2026-08-20 13:35:20)
)
| where InitiatingProcessFileName =~ "dllhost.exe"
| project TimeGenerated,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          RemoteIP,
          RemotePort,
          ActionType,
          InitiatingProcessRemoteSessionIP
```

At **1:35:17 PM**, `dllhost.exe` connected to:

- **Destination IP:** `85.210.196.11`
- **Port:** `443`
- **Result:** `ConnectionSuccess`
- **Remote Session IP:** `80.94.95.43`

The connection occurred during the same remote session.

<p align="center">
  <img src="https://imgur.com/TYqJ3ya.png" width="1200" alt="Outbound Connection During RDP Session">
</p>

---

## 4. Investigate MySQL Activity

I reviewed MySQL authentication and query activity after exposure.

```kusto
MySQLAudit_CL
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == "corp-na02-main"
| where RawData has "64.89.163.94"
    or RawData has "RECOVER_YOUR_DATA"
| project TimeGenerated,
          DeviceName,
          RawData
| order by TimeGenerated asc
```

A remote host at `64.89.163.94` connected to MySQL using the `root` account.

The following activity occurred:

1. **2:09:12 AM** — `root@64.89.163.94` connected through TCP/IP
2. **2:09:15 AM** — `DROP TABLE recover_your_data`
3. **2:09:15 AM** — A new `RECOVER_YOUR_DATA` table was created
4. **2:09:15 AM** — A Bitcoin ransom message was inserted

This confirmed unauthorized modification of the MySQL database.

<p align="center">
  <img src="https://imgur.com/S7JpF7I.png" width="1200" alt="Confirmed MySQL Ransom Activity">
</p>

---

## 5. Attack Timeline

### Windows VM

1. **Aug 20 — 1:34:54 PM** — `80.94.95.43` successfully logs in as `administrator`
2. **Aug 20 — 1:34:57 PM** — `rdpclip.exe` starts
3. **Aug 20 — 1:34:59 PM** — `userinit.exe` and `explorer.exe` start
4. **Aug 20 — 1:35:17 PM** — `dllhost.exe` connects to `85.210.196.11:443`
5. **Aug 20 — 1:36:30 PM** — `explorer.exe` launches `Taskmgr.exe`

### MySQL

6. **Aug 23 — 2:09:12 AM** — `64.89.163.94` connects as `root`
7. **Aug 23 — 2:09:15 AM** — Database modification begins
8. **Aug 23 — 2:09:15 AM** — Ransom table and Bitcoin payment message are created

---

## Phase 6 Findings

The investigation identified two compromise paths.

### Windows VM

`80.94.95.43` successfully logged into the `administrator` account using a `RemoteInteractive` session.

The session was followed by interactive process and network activity.

### MySQL Server

`64.89.163.94` successfully accessed MySQL using the `root` account and modified the database by creating a ransom table and inserting a Bitcoin payment message.

---

## Phase 7 Complete

The following telemetry sources were reviewed:

```text
DeviceLogonEvents
DeviceProcessEvents
DeviceNetworkEvents
MySQLAudit_CL
```
