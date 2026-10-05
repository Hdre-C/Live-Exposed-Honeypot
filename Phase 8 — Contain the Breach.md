# Phase 8 — Contain the Breach

After completing the breach analysis, I contained the compromised honeypot using Microsoft Defender for Endpoint.

The goal of this phase was to isolate `corp-na02-main` and preserve a post-breach investigation package for later comparison.

---

## 1. Isolate the Compromised VM

The VM was kept powered on and isolated through the Microsoft Defender portal.

Device:

```text
corp-na02-main
```

Isolating the device prevents normal network communication while allowing Microsoft Defender to continue communicating with the endpoint.

### 📸 Image 1 — Device Isolation

Capture the Defender device page showing that `corp-na02-main` has been isolated.

Show:

- Device name
- Isolation status
- Isolation action/result

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="Defender Device Isolation">
</p>

---

## 2. Record the Isolation Time

The exact isolation time was recorded for use in the final incident timeline.

```text
Isolation Time: YOUR_ISOLATION_TIMESTAMP
```

Example format:

```text
2026-08-XXTXX:XX:XX.XXXXXXXZ
```

This timestamp marks the end of the exposure period and will be used when exporting logs for the final incident report.

---

## 3. Capture the Post-Breach Investigation Package

After isolating the VM, I collected another Investigation Package through Microsoft Defender.

This package represents the state of the VM **after the compromise**.

The post-breach package will later be compared with the **pre-breach Investigation Package captured in Phase 5**.

### 📸 Image 2 — Post-Breach Investigation Package

Capture the Defender page showing the investigation package collection request or completed package.

Show:

- Device name
- Investigation package
- Collection status
- Date/time

<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="Post-Breach Investigation Package">
</p>

---

## Phase 8 Complete

Containment was completed by:

```text
Compromised VM
      ↓
Microsoft Defender Isolation
      ↓
Isolation Time Recorded
      ↓
Post-Breach Investigation Package Captured
```

The environment was now contained and ready for **Phase 9 — Eradication and Recovery**.
