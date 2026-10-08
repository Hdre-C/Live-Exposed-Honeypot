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

![Payload Download](https://i.postimg.cc/m2qnt6Hz/image-2026-10-07-215406729.png)

## 2. Record the Isolation Time

The exact isolation time was recorded for use in the final incident timeline.

```text
Isolation Time: 2026-08-27T04:30:52.7989242Z
```

This timestamp marks the end of the exposure period and will be used when exporting logs for the final incident report.

---

## 3. Capture the Post-Breach Investigation Package

After isolating the VM, I collected another Investigation Package through Microsoft Defender.

This package represents the state of the VM **after the compromise**.

The post-breach package will later be compared with the **pre-breach Investigation Package captured in Phase 5**.

![Payload Download](https://i.postimg.cc/JhR5nbPB/image-2026-10-07-215805372.png)
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
