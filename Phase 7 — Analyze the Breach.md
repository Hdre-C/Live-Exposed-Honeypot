# Phase 7 — Analyze the Breach

In this phase, I investigated the activity captured after the honeypot was exposed.

The goal was to determine:

- How the attacker gained access
- Which account was compromised
- What commands and processes were executed
- What files or persistence mechanisms were created
- What external systems the VM communicated with
- Whether the MySQL database was accessed

---

## 1. Investigate Successful VM Logins

I first reviewed successful authentication events after the Phase 5 exposure time.

```kusto
let MyDevice = "corp-na02-main";
let ServerVulnerableDateTime = todatetime("YOUR_EXPOSURE_TIMESTAMP");

DeviceLogonEvents
| where TimeGenerated > ServerVulnerableDateTime
| where DeviceName == MyDevice
| where AccountName in~ ("administrator", "guest")
| where ActionType == "LogonSuccess"
| project TimeGenerated, RemoteIP, AccountName, DeviceName, ActionType, LogonType
| order by TimeGenerated asc
```

This identifies the **source IP, account, and time of successful access**.

> 📸 **IMAGE 1 — Successful Login**
>
> Screenshot the first suspicious successful login.
>
> Show:
>
> - Timestamp
> - Remote IP
> - Account
> - `LogonSuccess`
> - Device name

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="Successful Honeypot Login">
</p>

---

## 2. Investigate Process Activity

After identifying a successful login, I reviewed processes executed on the VM.

```kusto
let MyDevice = "corp-na02-main";
let BreachTime = todatetime("YOUR_SUCCESSFUL_LOGIN_TIMESTAMP");

DeviceProcessEvents
| where DeviceName == MyDevice
| where Timestamp >= BreachTime
| where AccountName in~ ("administrator", "guest")
| project Timestamp,
          AccountName,
          FileName,
          ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp asc
```

This helps identify:

- Reconnaissance commands
- PowerShell activity
- Download commands
- Security tampering
- Persistence attempts

> 📸 **IMAGE 2 — Suspicious Process Activity**
>
> Screenshot the most important process activity after the login.
>
> Try to show:
>
> - Timestamp
> - Process name
> - Command line
> - Initiating process
> - Account

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="Post-Compromise Process Activity">
</p>

---

## 3. Investigate Network Activity

I then reviewed outbound network connections from the compromised VM.

```kusto
let MyDevice = "corp-na02-main";
let BreachTime = todatetime("YOUR_SUCCESSFUL_LOGIN_TIMESTAMP");

DeviceNetworkEvents
| where DeviceName == MyDevice
| where Timestamp >= BreachTime
| project Timestamp,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          RemoteIP,
          RemotePort,
          RemoteUrl,
          ActionType
| order by Timestamp asc
```

This can reveal communication with:

- Payload-hosting servers
- Suspicious external IPs
- Possible command-and-control infrastructure

> 📸 **IMAGE 3 — Suspicious Network Connection**
>
> Screenshot an unusual external connection related to the compromise.
>
> Show:
>
> - Timestamp
> - Process
> - Remote IP
> - Remote port
> - Remote URL if available

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="Suspicious Network Activity">
</p>

---

## 4. Investigate File Activity

`DeviceFileEvents` was used to identify files created, downloaded, or modified after the breach.

```kusto
let MyDevice = "corp-na02-main";
let BreachTime = todatetime("YOUR_SUCCESSFUL_LOGIN_TIMESTAMP");

DeviceFileEvents
| where DeviceName == MyDevice
| where Timestamp >= BreachTime
| project Timestamp,
          ActionType,
          FileName,
          FolderPath,
          SHA256,
          InitiatingProcessFileName
| order by Timestamp asc
```

Suspicious executables or files created shortly after the login were prioritized for investigation.

> 📸 **IMAGE 4 — File Activity**
>
> Screenshot any suspicious downloaded or created file.
>
> Show:
>
> - File name
> - Folder path
> - Action type
> - Initiating process
> - SHA256 if available

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="Suspicious File Activity">
</p>

---

## 5. Investigate Registry Activity

Registry telemetry was reviewed for possible persistence or system changes.

```kusto
let MyDevice = "corp-na02-main";
let BreachTime = todatetime("YOUR_SUCCESSFUL_LOGIN_TIMESTAMP");

DeviceRegistryEvents
| where DeviceName == MyDevice
| where Timestamp >= BreachTime
| project Timestamp,
          ActionType,
          RegistryKey,
          RegistryValueName,
          RegistryValueData,
          InitiatingProcessFileName
| order by Timestamp asc
```

> 📸 **IMAGE 5 — Registry Activity**
>
> Only include this image if meaningful registry changes were found.
>
> Show the suspicious registry key/value and the process responsible.

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="Suspicious Registry Activity">
</p>

---

## 6. Investigate MySQL Activity

If MySQL was accessed, I reviewed the query log to determine what commands were executed.

```kusto
let MyDevice = "corp-na02-main";
let ServerVulnerableDateTime = todatetime("YOUR_EXPOSURE_TIMESTAMP");

MySQLAudit_CL
| where TimeGenerated > ServerVulnerableDateTime
| where RawData has "Query"
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| extend ActionType = "Query"
| extend Query = split(RawData, "Query")[1]
| project TimeGenerated,
          DeviceName,
          ActionType,
          Query,
          RawData
| order by TimeGenerated asc
```

This helps determine whether the attacker attempted to **view, modify, or extract data** from the `lnp_corp` database.

> 📸 **IMAGE 6 — MySQL Activity**
>
> If suspicious MySQL activity exists, screenshot the queries executed after the breach.
>
> Show:
>
> - Timestamp
> - Device name
> - SQL query
> - Raw log entry

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="Suspicious MySQL Activity">
</p>

---

## 7. Review Denied Outbound Traffic

`NTANetAnalytics` was also reviewed for outbound traffic attempts from the compromised VM.

```kusto
let MyDevice = "corp-na02-main";

NTANetAnalytics
| where isnotempty(SrcVm)
| where SrcVm endswith MyDevice
| where DeniedOutFlows >= 1
| project TimeGenerated,
          DeviceName = MyDevice,
          FlowType,
          FlowStatus,
          SrcIp,
          SrcPorts,
          DestIp,
          DestPort
| order by TimeGenerated asc
```

This can reveal attempted outbound communication that was blocked by the environment.

> 📸 **IMAGE 7 — Outbound Traffic**
>
> Include this screenshot if suspicious denied outbound traffic was observed.
>
> Show:
>
> - Timestamp
> - Source IP
> - Destination IP
> - Destination port
> - Flow status

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="Denied Outbound Traffic">
</p>

---

## 8. Build the Attack Timeline

After correlating the logs, I created a timeline of the important events.

Example format:

1. **[TIME]** — Successful attacker login
2. **[TIME]** — Remote command execution begins
3. **[TIME]** — System reconnaissance
4. **[TIME]** — Security controls modified
5. **[TIME]** — Payload downloaded
6. **[TIME]** — Persistence established
7. **[TIME]** — Additional network or database activity

> Replace the example events above with the activity actually observed in your logs.

---

## Phase 7 Complete

At the end of Phase 7, telemetry from multiple sources was correlated to reconstruct the attack:

```text
Authentication
      ↓
Process Activity
      ↓
File / Registry Changes
      ↓
Network Activity
      ↓
MySQL Activity
      ↓
Attack Timeline
```

The findings from this investigation will be used in **Phase 8 — Contain the Breach**.
