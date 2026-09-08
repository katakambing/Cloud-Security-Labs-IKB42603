# IKB42603 Cloud Computing Security Essentials — Lab 5: Monitoring, Logging & Incident Detection

**Student:** WAN MUHAMMAD NUR IMAN BIN WAN ISMAIL  
**Student ID:** 52215225039  
**Branch:** `lab5`  

---

## 📌 Executive Summary

This lab demonstrates centralized cloud logging, tamper-evident hash chaining, multi-event threat correlation, and the end-to-end incident response lifecycle (Contain, Collect, Document) using Docker and AWS CloudWatch Logs (via LocalStack).

👉 **[Click here to view the Full Lab Report & Evidence Details](Lab5/Lab5_Monitoring_Logging_and_Incident_Detection.md)**

---

## 🎯 Key Learning Highlights & Results

| Task / Domain | Security Concept | Implementation | Verification Status |
| :--- | :--- | :--- | :---: |
| **Task 1: Log Generation** | Application Telemetry | Authentication log simulation with brute-force probing | In Progress |
| **Task 2: Centralization** | CloudWatch Logs Ingestion | Cascading log shipping to `/ccse/app` stream | In Progress |
| **Task 3: Log Querying** | Threat Hunting Baseline | Aggregating & filtering failed login attempts by IP | In Progress |
| **Task 4: Tamper-Proofing** | Hash-Chained Audit Trails | SHA-256 recursive chaining & tampering detection | In Progress |
| **Task 5: Incident Correlation**| SIEM Multi-Event Detection | Correlating failed logins → success → exfiltration | In Progress |
| **Task 6: Incident Response** | Containment & Forensics | Host iptables blocking & cryptographic evidence collection | In Progress |

---

## 📁 Branch Structure

```text
lab5
  Lab5/
    Lab5_Monitoring_Logging_and_Incident_Detection.md
    Evidence/
```

🔗 *Return to [Main Landing Page](https://github.com/katakambing/Cloud-Security-Labs-IKB42603)*
