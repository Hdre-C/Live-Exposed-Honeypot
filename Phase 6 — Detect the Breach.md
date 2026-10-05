In this phase, the honeypot remained online while **Microsoft Sentinel and Defender** monitored for real attacker activity.

The goal was to identify:

- Windows login attempts
- Successful VM logins
- MySQL authentication activity
- Sentinel incidents triggered by the Phase 4 detection rules

---

## 1. Monitor VM Authentication

`DeviceLogonEvents` was used to monitor login activity against the honeypot after it was exposed.

```kusto
let MyDevice = "corp-na02-main";
let ServerVulnerableDateTime = todatetime("2026-08-20T03:46:46.4049687Z");

DeviceLogonEvents
| where TimeGenerated > ServerVulnerableDateTime
| where DeviceName == MyDevice
| where AccountName in~ ("administrator", "guest")
| project TimeGenerated, RemoteIP, AccountName, DeviceName, ActionType, LogonType
| order by TimeGenerated desc
```

This shows who attempted to authenticate, the source IP, targeted account, and whether the login succeeded or failed.

> 📸 **IMAGE 1 — VM Authentication Activity**
>
> Run the query above and screenshot the results.
>
> Make sure these columns are visible:
>
> - `TimeGenerated`
> - `RemoteIP`
> - `AccountName`
> - `ActionType`
> - `LogonType`

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="VM Authentication Activity">
</p>

---

## 2. Monitor MySQL Authentication

`MySQLAudit_CL` was monitored for authentication attempts against the MySQL server.

```kusto
let MyDevice = "corp-na02-main";
let MyTimeframe = todatetime("YOUR_EXPOSURE_TIMESTAMP");

let FailedConnections =
MySQLAudit_CL
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| where RawData has "Access denied"
| extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
| distinct ConnectionId;

MySQLAudit_CL
| where TimeGenerated > MyTimeframe
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
| where ActionType != "Ignore"
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

This separates MySQL activity into **successful and failed authentication attempts**.

> 📸 **IMAGE 2 — MySQL Authentication Activity**
>
> Screenshot the query results showing:
>
> - `TimeGenerated`
> - `Username`
> - `IpAddress`
> - `ActionType`
>
> Try to capture both failed and successful authentication activity if available.

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="MySQL Authentication Activity">
</p>

---

## 3. Monitor MySQL Queries

If an attacker successfully authenticates to MySQL, the query logs can show what they did inside the database.

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
| order by TimeGenerated desc
```

This provides visibility into commands executed against the `lnp_corp` database.

> 📸 **IMAGE 3 — MySQL Query Activity**
>
> If MySQL was successfully accessed, screenshot any suspicious queries.
>
> Make sure the following are visible:
>
> - Timestamp
> - Device name
> - SQL query
> - Raw log data

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="MySQL Query Activity">
</p>

---

## 4. Monitor Sentinel Incidents

The **Sentinel Analytics Rules created in Phase 4** were monitored for alerts after the honeypot became publicly accessible.

A triggered rule indicates activity that matched one of the configured detections.

> 📸 **IMAGE 4 — Sentinel Incident**
>
> When a detection triggers, take a screenshot of the Sentinel incident showing:
>
> - Incident name
> - Severity
> - Status
> - Created time
> - Related IP/account if visible

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="Microsoft Sentinel Incident">
</p>

---

## 5. Investigate Activity After a Successful Login

If a successful VM login is detected, additional Defender tables can be used to see what happened next:

```text
DeviceProcessEvents
DeviceFileEvents
DeviceRegistryEvents
DeviceNetworkEvents
```

These tables provide visibility into **commands, processes, files, registry changes, and network activity** performed after access was gained.

Detailed investigation of this activity is performed in **Phase 7**.

---

## Phase 6 Complete

At the end of Phase 6:

- The exposed honeypot remained under active monitoring
- Windows authentication activity was monitored
- MySQL authentication activity was monitored
- MySQL queries were monitored
- Sentinel detection rules were watched for incidents
- Suspicious activity was identified for deeper investigation in **Phase 7**

The next phase focuses on reconstructing what the attacker did after gaining access.
