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


![Payload Download](https://imgur.com/fgGjYtK.png)

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

![Payload Download](https://imgur.com/2IvzVDD.png)
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

![Payload Download](https://imgur.com/JMbnL7s.png)

---

## Phase 3 Complete

At the end of Phase 3:

- The **Azure Monitor Agent** is collecting the MySQL log
- A **Data Collection Rule** controls log ingestion
- `mysql_general.log` is sent to `LAW-Cyber-Range`
- MySQL events are available in `MySQLAudit_CL`
- The logs can now be investigated using **KQL**

The honeypot now has centralized MySQL telemetry ready for later attack analysis.
