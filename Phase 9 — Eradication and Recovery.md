# Phase 9 — Eradication and Recovery

After containing the compromised VM, I moved into eradication and recovery.

The goal was to remove the intentionally weakened configuration, secure the Windows VM and MySQL server, and restore the database.

---

## 1. Harden the Network Security Group

The NSG rules created for the honeypot exposure were removed or restricted.

Public access to the VM was no longer left open to the internet.

The NSG was returned to a hardened configuration before the VM was removed from Defender isolation.

[![image-2026-10-07-222410833.png](https://i.postimg.cc/J7361z1P/image-2026-10-07-222410833.png)](https://postimg.cc/6T3Lcw4v)

---

## 2. Remove the VM from Isolation

After the network controls were hardened, `corp-na02-main` was removed from Microsoft Defender isolation.

```text
Device: corp-na02-main
Status: Released from isolation
```

---

## 3. Run a Full Microsoft Defender Scan

A full malware scan was performed on the VM using Microsoft Defender.

This was used to check the system for any remaining malicious files or software after the compromise.

### 📸 Image 2 — Full Defender Scan

Capture the Defender page showing the full malware scan request or completed scan.

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="Microsoft Defender Full Scan">
</p>

---

## 4. Re-enable Windows Firewall

The Windows Firewall, which had been disabled during the honeypot exposure phase, was re-enabled.

```text
Windows Defender Firewall: Enabled
```

Firewall protection was restored for all profiles.

---

## 5. Harden Local Accounts

The weak accounts used during the honeypot phase were removed or disabled.

The following changes were made:

- Removed the intentionally weakened `administrator` account
- Disabled the `guest` account
- Kept only a local account protected with a strong password

### 📸 Image 3 — Account Hardening

Capture the Windows account configuration showing the hardened local accounts.

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="Windows Account Hardening">
</p>

---

## 6. Harden MySQL

The MySQL server was also secured after the compromise.

Remote public access to MySQL was removed.

The weak remote `root` account created during the honeypot phase was removed or protected with a strong password.

MySQL should no longer accept unrestricted connections from the public internet.

Example cleanup:

```sql
DROP USER 'root'@'%';
FLUSH PRIVILEGES;
```

The local administrative MySQL account remained protected with a strong password.

### 📸 Image 4 — MySQL Hardening

Capture MySQL Workbench showing that the unrestricted remote `root@%` account is no longer present.

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="MySQL Account Hardening">
</p>

---

## 7. Restore the Database

Because the MySQL database had been modified by an unauthorized external host, the affected data was restored from the original clean dataset or backup.

The `lnp_corp` database was returned to its known-good state.

The attacker-created ransom table was no longer part of the recovered database.

### 📸 Image 5 — Restored Database

Capture MySQL Workbench showing the restored `lnp_corp` schema and normal database tables.

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="Restored MySQL Database">
</p>

---

## Phase 9 Complete

The compromised environment was recovered by:

```text
Harden NSG
     ↓
Remove Defender Isolation
     ↓
Run Full Malware Scan
     ↓
Enable Windows Firewall
     ↓
Harden Local Accounts
     ↓
Remove Public MySQL Access
     ↓
Secure MySQL Accounts
     ↓
Restore Database
```

The environment was returned to a hardened state and was ready for **Phase 10 — Reporting**.
