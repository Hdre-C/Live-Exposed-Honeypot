## Phase 0 — Honeypot Architecture
![Honeypot Architecture](https://i.imgur.com/gSl6Wkp.png)

Before exposing the honeypot, I built the **Azure environment and logging pipeline** needed to capture and investigate attacker activity.

### 1. Attacker Traffic → Honeypot

Internet traffic passes through the **Network Security Group (NSG)** before reaching the Windows 11 honeypot.

Main attack surfaces:

- **RDP — Port 3389**
- **MySQL — Port 3306**
- **Weak test accounts** for capturing brute-force and login activity

> In **Phase 5**, the NSG rules will be changed to expose the honeypot to the public internet.

### 2. MySQL → Log Analytics

MySQL records connections and queries in `mysql_general.log`.

The **Azure Monitor Agent (AMA)** sends these logs to the **Log Analytics Workspace (`LAW-Cyber-Range`)**.

MySQL → mysql_general.log → AMA → Log Analytics

These logs can then be investigated using **KQL**.

### 3. VM Activity → Microsoft Defender

The honeypot is connected to **Microsoft Defender for Endpoint (MDE)** to capture activity inside the VM, including:

- Logins
- Processes and commands
- File activity
- Network connections
- Persistence activity
- Security changes

> **Phase 0 Goal:** Build the honeypot and confirm logging and monitoring are working before exposing it to real attackers in **Phase 5**.
