# Phase 5 — Weaken & Expose the Honeypot

In this phase, the honeypot was intentionally weakened and exposed to the internet so real attacker activity could be captured.

> ⚠️ These settings are intentionally insecure and are only used inside this controlled honeypot environment.

---

## 1. Create Weak Windows Accounts

The local `Administrator` and `Guest` accounts were configured as easy targets for password attacks.

### Administrator

- Enabled the `Administrator` account
- Added it to the **Administrators** group
- Assigned a weak password

### Guest

- Enabled the `Guest` account
- Added it to the **Users** group
- Allowed the account to use Remote Desktop

After changing the local security policies, I applied them with:

```powershell
gpupdate /force
```

> 📸 **IMAGE 1 — Weak Accounts**
>
> Take a screenshot of **Computer Management → Local Users and Groups** showing:
>
> - `Administrator`
> - `Guest`
> - Both accounts enabled

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="Weak Honeypot Accounts">
</p>

---

## 2. Allow Remote MySQL Authentication

MySQL was configured to allow the `root` account to authenticate remotely.

```sql
CREATE USER 'root'@'%' IDENTIFIED BY 'root';

GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;

FLUSH PRIVILEGES;
```

The `%` allows the account to attempt authentication from remote systems rather than only locally.

> 📸 **IMAGE 2 — Remote MySQL Account**
>
> Take a screenshot in **MySQL Workbench** showing the commands being executed successfully.

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="Remote MySQL Authentication">
</p>

---

## 3. Capture the Pre-Breach Investigation Package

Before exposing the VM, I captured a **Microsoft Defender Investigation Package**.

This provides a clean **pre-breach snapshot** that can later be compared with the post-compromise package.

> 📸 **IMAGE 3 — Pre-Breach Investigation Package**
>
> Take a screenshot from Microsoft Defender showing the investigation package being collected or completed.

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="Pre-Breach Investigation Package">
</p>

---

## 4. Disable Windows Firewall

The Windows Firewall was disabled to increase the attack surface of the honeypot.

This was done through:

```text
wf.msc
```

The VM is now intentionally less protected from inbound connections.

---

## 5. Expose the VM to the Internet

The Azure **Network Security Group (NSG)** was changed from the locked-down configuration used during setup to allow inbound internet traffic.

This makes services such as:

- **RDP — Port 3389**
- **MySQL — Port 3306**

reachable by external systems.

> 📸 **IMAGE 4 — NSG Exposure**
>
> Take a screenshot of the VM's **NSG inbound rules** showing that internet traffic is now allowed.
>
> Make sure the rule priority, action, source, and destination are visible.

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="Honeypot NSG Exposure">
</p>

---

## 6. Record the Exposure Time

The exact time the NSG was opened was recorded.

```text
Exposure Timestamp: ______________________________
```

This timestamp marks the **start of the live incident window** and will later be used to determine how long it took before the honeypot was attacked.

> 📸 **IMAGE 5 — Exposure Timestamp**
>
> Take a screenshot showing the NSG rule change or Azure activity log with the timestamp visible.

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="Honeypot Exposure Timestamp">
</p>

---

## 7. Confirm Detections Are Active

Before leaving the honeypot exposed, I confirmed that the Phase 4 Sentinel detection rules were still enabled.

```text
Weak Accounts
      ↓
Firewall Disabled
      ↓
NSG Opened
      ↓
Honeypot Exposed
      ↓
Sentinel Monitoring
```

---

## Phase 5 Complete

At the end of Phase 5:

- Weak Windows accounts are enabled
- Remote MySQL authentication is enabled
- A pre-breach investigation package has been captured
- Windows Firewall is disabled
- The NSG allows inbound internet traffic
- The exact exposure timestamp is recorded
- Sentinel detections are active

The honeypot is now **live and exposed to real-world attacker traffic**.
