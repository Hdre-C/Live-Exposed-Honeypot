# Phase 9 — Eradication and Recovery

After containing the compromised VM, I moved into eradication and recovery.

The goal was to remove the intentionally weakened configuration, secure the Windows VM and MySQL server, and restore the database.

---

## 1. Harden the Network Security Group

The NSG rules created for the honeypot exposure were removed or restricted.

Public access to the VM was no longer left open to the internet.

The NSG was returned to a hardened configuration before the VM was removed from Defender isolation.

![Payload Download](https://imgur.com/2xiPc61.png)

---

## 2. Remove the VM from Isolation

After the network controls were hardened, `corp-na02-main` was removed from Microsoft Defender isolation.

![Payload Download](https://imgur.com/zUkTN3f.png)
---

## 3. Run a Full Microsoft Defender Scan

A full malware scan was performed on the VM using Microsoft Defender.

This was used to check the system for any remaining malicious files or software after the compromise.

![Payload Download](https://imgur.com/3QVKQs3.png)
---

## 4. Re-enable Windows Firewall

The Windows Firewall, which had been disabled during the honeypot exposure phase, was re-enabled.

![Payload Download](https://imgur.com/0ovqDx8.png)
---

## 5. Harden Local Accounts

The weak accounts used during the honeypot phase were removed or disabled.

The following changes were made:

- Removed the intentionally weakened `administrator` account
- Disabled the `guest` account
- Kept only a local account protected with a strong password

![Payload Download](https://imgur.com/lO7Ona2.png)
![Payload Download](https://imgur.com/ykq39wg.png)
![Payload Download](https://imgur.com/VFAFwAV.png)
---

## 6. Harden MySQL

The MySQL server was also secured after the compromise.

Remote public access to MySQL was removed.

The weak remote `root` account created during the honeypot phase was removed and local root account protected with a strong password.

MySQL should no longer accept unrestricted connections from the public internet.

![Payload Download](https://imgur.com/9mROjLL.png)
![Payload Download](https://imgur.com/iHkI7ud.png)
---

## 7. Restore the Database

Because the MySQL database had been modified by an unauthorized external host, the affected data was restored from the original clean dataset or backup.

The `lnp_corp` database was returned to its known-good state.

The attacker-created ransom table was no longer part of the recovered database.

![Payload Download](https://imgur.com/iylYuc5.png)
![Payload Download](https://imgur.com/8rTjTKH.png)

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
