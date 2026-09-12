# Phase 3 — Ingest MySQL Logs into Log Analytics

In this phase, the MySQL logs from the honeypot VM are collected with the **Azure Monitor Agent (AMA)** and sent to the **Log Analytics Workspace** for KQL analysis.

---

## 1. Create the Data Collection Rule

A **Data Collection Rule (DCR)** was created in Azure to collect the MySQL general log from the VM.

The log file configured in Phase 2 is:

```text
C:\ProgramData\MySQL\MySQL Server 8.0\Data\mysql_general.log
```

The honeypot VM was added as a resource for the DCR.

> 📸 **IMAGE 1 — Data Collection Rule**
>
> Take a screenshot of the DCR overview showing:
>
> - DCR name
> - Honeypot VM
> - Region
> - Log Analytics destinationhttps://imgur.com/fgGjYtK

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="MySQL Data Collection Rule">
</p>

---

## 2. Configure the Custom Text Log

The DCR was configured to monitor:

```text
C:\ProgramData\MySQL\MySQL Server 8.0\Data\mysql_general.log
```

The collected MySQL events are sent into the custom Log Analytics table:

```text
MySQLAudit_CL
```

This allows MySQL connections and queries to be searched using **KQL**.

> 📸 **IMAGE 2 — MySQL Log Source**
>
> Take a screenshot of the DCR configuration showing the `mysql_general.log` file path and the custom table destination.

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="MySQL Custom Text Log Configuration">
</p>

---

## 3. Send Logs to Log Analytics

The **Azure Monitor Agent (AMA)** reads the MySQL log file from the VM and forwards the events to the Log Analytics Workspace.

```text
MySQL
   ↓
mysql_general.log
   ↓
Azure Monitor Agent
   ↓
Data Collection Rule
   ↓
Log Analytics
```

The destination workspace used for the project is:

```text
LAW-Cyber-Range
```

---

## 4. Verify Log Ingestion

After running several MySQL queries, I checked the custom table in Log Analytics.

```kusto
MySQLAudit_CL
| order by TimeGenerated desc
```

The query confirmed that MySQL activity was successfully reaching Azure.

> 📸 **IMAGE 3 — MySQL Logs in Log Analytics**
>
> Run the query above and take a screenshot showing:
>
> - `MySQLAudit_CL`
> - Recent timestamps
> - MySQL query/log data
> - Multiple ingested events

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="MySQL Logs in Log Analytics">
</p>

---

## 5. Confirm End-to-End Logging

A few test queries were executed in MySQL Workbench and then searched for in Log Analytics.

Example:

```sql
USE lnp_corp;

SELECT *
FROM users
LIMIT 10;
```

The same activity should appear inside `MySQLAudit_CL`, confirming the full logging pipeline is working.

> 📸 **IMAGE 4 — End-to-End Verification**
>
> Take a screenshot of a MySQL query from Workbench and the matching event inside Log Analytics.
>
> This shows that activity on the VM is successfully being collected and ingested into Azure.

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="MySQL End-to-End Log Verification">
</p>

---

## Phase 3 Complete

At the end of Phase 3:

- The **Azure Monitor Agent** is collecting the MySQL log
- A **Data Collection Rule** controls log ingestion
- `mysql_general.log` is sent to `LAW-Cyber-Range`
- MySQL events are available in `MySQLAudit_CL`
- The logs can now be investigated using **KQL**

The honeypot now has centralized MySQL telemetry ready for later attack analysis.
