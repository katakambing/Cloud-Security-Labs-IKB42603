# IKB42603 Cloud Computing Security Essentials — Lab 4: Access Control & Network Security

**Student:** WAN MUHAMMAD NUR IMAN BIN WAN ISMAIL  
**Student ID:** 52215225039  
**Branch:** `lab4`  

---

## 📌 Executive Summary

This lab demonstrates the implementation of identity verification, granular authorization, network segmentation, default-deny host firewalls, container runtime hardening, and vulnerability scanning using Docker and Kubernetes.

👉 **[Click here to view the Full Lab Report & Evidence Details](Lab4/Lab4_Access_Control_and_Network_Security.md)**

---

## 🎯 Key Learning Highlights & Results

| Task / Domain | Security Concept | Implementation | Verification Status |
| :--- | :--- | :--- | :---: |
| **Task 1: Authentication** | Identity Verification (AuthN) | NGINX HTTP Basic Auth (401 unauthenticated / 200 OK) | **VERIFIED** |
| **Task 2: MFA / TOTP** | Multi-Factor Authentication | RFC 6238 time-step token verification (`MFA OK`) | **VERIFIED** |
| **Task 3: RBAC AuthZ** | Least-Privilege Authorization | Kubernetes Role & RoleBinding (`yes` read / `no` write) | **VERIFIED** |
| **Task 4: Segmentation** | Defense in Depth & Blast Radius | Three-tier Docker subnets (Web $\rightarrow$ DB `BLOCKED`) | **VERIFIED** |
| **Task 5: Firewall** | Default-Deny Posture | `iptables -P INPUT DROP` with explicit port 443 allow | **VERIFIED** |
| **Task 6: Hardening** | Runtime Attack Surface Reduction| Non-root, read-only rootfs, `cap-drop=ALL`, `tmpfs` | **VERIFIED** |
| **Task 6: Vulnerability Scan**| Pre-Deployment Inspection | Aquasec Trivy container image scan for known CVEs | **VERIFIED** |

---

## 📁 Branch Structure

```text
lab4
  Lab4/
    Lab4_Access_Control_and_Network_Security.md
    Evidence/
```

🔗 *Return to [Main Landing Page](https://github.com/katakambing/Cloud-Security-Labs-IKB42603)*
