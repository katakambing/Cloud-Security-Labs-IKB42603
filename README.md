# IKB42603 Cloud Computing Security Essentials — Lab 2: Secure Isolation & Multi-Tenancy

**Student:** WAN MUHAMMAD NUR IMAN BIN WAN ISMAIL  
**Student ID:** 52215225039  
**Branch:** `lab2`  

---

## 📌 Executive Summary

This lab investigates multi-tenant cloud isolation, container network security, resource governance, and secure data sanitization. It demonstrates how Kubernetes namespaces, NetworkPolicies, ResourceQuotas, RBAC, and cryptographic data wiping prevent cross-tenant eavesdropping, noisy-neighbor denial of service, and data remanence attacks.

👉 **[Click here to view the Full Lab Report & Evidence Details](Lab2/Lab2_Secure_Isolation_and_Multi_Tenancy.md)**

---

## 🎯 Key Learning Highlights & Results

| Task / Domain | Security Concept | Implementation | Verification Status |
| :--- | :--- | :--- | :---: |
| **Task 1: Multi-Tenancy** | Workload Partitioning | Tenant A and Tenant B isolated pods & services | **VERIFIED** |
| **Task 2: Default-Open Risk** | Lateral Movement Threat | Probing cross-tenant communication on default network | **VERIFIED** |
| **Task 3: Resource Quotas** | DoS / Noisy-Neighbor Mitigation | CPU & memory quota enforcement per namespace | **VERIFIED** |
| **Task 4: NetworkPolicy** | Zero-Trust Microsegmentation | Ingress deny policy resulting in probe timeout | **VERIFIED** |
| **Task 5: RBAC Isolation** | Secret Confidentiality | Tenant user prevented from reading cross-tenant secrets | **VERIFIED** |
| **Task 6: Data Remanence** | Storage Sanitization | Cryptographic zero-fill overwrite & data wipe verification | **VERIFIED** |

---

## 📁 Branch Structure

```text
lab2
  Lab2/
    Lab2_Secure_Isolation_and_Multi_Tenancy.md
    Evidence/
```

🔗 *Return to [Main Landing Page](https://github.com/katakambing/Cloud-Security-Labs-IKB42603)*
