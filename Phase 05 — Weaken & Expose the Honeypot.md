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

![Payload Download](https://imgur.com/nTqZHvA.png)

![Payload Download](https://imgur.com/gEk4gkB.png)

![Payload Download](https://imgur.com/rdQU6DR.png)

![Payload Download](https://imgur.com/4NKTXs2.png)

![Payload Download](https://imgur.com/rtLCXsi.png)

---

## 2. Allow Remote MySQL Authentication

MySQL was configured to allow the `root` account to authenticate remotely.

```sql
CREATE USER 'root'@'%' IDENTIFIED BY 'root';

GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;

FLUSH PRIVILEGES;
```

The `%` allows the account to attempt authentication from remote systems rather than only locally.

![Payload Download](https://imgur.com/2O2G47r.png)

---

## 3. Capture the Pre-Breach Investigation Package

Before exposing the VM, I captured a **Microsoft Defender Investigation Package**.

This provides a clean **pre-breach snapshot** that can later be compared with the post-compromise package.

![Payload Download](https://imgur.com/ddFFCPt.png)

---

## 4. Disable Windows Firewall

The Windows Firewall was disabled to increase the attack surface of the honeypot.

This was done through:

```text
wf.msc
```

The VM is now intentionally less protected from inbound connections.

![Payload Download](https://imgur.com/Md0io1m.png)
---

## 5. Expose the VM to the Internet

The Azure **Network Security Group (NSG)** was changed from the locked-down configuration used during setup to allow inbound internet traffic.

This makes services such as:

- **RDP — Port 3389**
- **MySQL — Port 3306**

reachable by external systems.

![Payload Download](https://imgur.com/5y54EJX.png)

---

## 6. Record the Exposure Time

The exact time the NSG was opened was recorded.

```text
Exposure Timestamp: 2026-08-20T03:46:46.4049687Z
```

This timestamp marks the **start of the live incident window** and will later be used to determine how long it took before the honeypot was attacked.

---

## Phase 5 Complete

At the end of Phase 5:

- Weak Windows accounts are enabled
- Remote MySQL authentication is enabled
- A pre-breach investigation package has been captured
- Windows Firewall is disabled
- The NSG allows inbound internet traffic
- The exact exposure timestamp is recorded

The honeypot is now **live and exposed to real-world attacker traffic**.
