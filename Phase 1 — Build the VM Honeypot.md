# Phase 1 — Build the VM Honeypot

In this phase, I deployed the **Windows 11 VM** that will act as the honeypot. The VM remains locked down while the environment is being configured.

### 1. Deploy the Windows 11 VM

![Phase 1 - VM Honeypot](https://i.imgur.com/dJzVKSr.png)

- Created a **Windows 11 VM** in Microsoft Azure.
- Assigned the VM a **public IP address**.
- Used a strong administrator username and password.
- Named the VM **`CORP-NA02-MAIN`** to resemble a legitimate corporate system.

### 2. Lock Down Inbound Traffic

![Microsoft Defender for Endpoint - Device Onboarding](https://i.imgur.com/8iqvCni.png)

The **Network Security Group (NSG)** was configured to deny inbound internet traffic while the honeypot is being built.

> The VM will remain protected until **Phase 5**, when the NSG is opened and the honeypot is intentionally exposed to the internet.

### 3. Onboard to Microsoft Defender for Endpoint

![Microsoft Defender for Endpoint - Device Verification](https://i.imgur.com/txhfcXS.png)

![Honeypot Setup](https://i.imgur.com/BGTAHPt.png)

The VM was onboarded to **Microsoft Defender for Endpoint (MDE)** to collect security telemetry.

After onboarding, I verified that the VM appeared in the **`DeviceInfo`** table using Advanced Hunting.

> **Phase 1 Goal:** Deploy the honeypot VM, keep it protected during setup, and verify that Microsoft Defender for Endpoint is successfully monitoring the device.
