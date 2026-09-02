# IKB42603 Cloud Computing Security Essentials — Lab 1: Account Security & IAM

**Student:** WAN MUHAMMAD NUR IMAN BIN WAN ISMAIL  
**Student ID:** 52215225039  
**Branch:** `lab1`  

---

## 📌 Executive Summary

This lab implements robust Identity and Access Management (IAM) and Account Security controls across AWS (via LocalStack) and Kubernetes. It demonstrates the Principle of Least Privilege by configuring administrative and read-only IAM groups, managing access key lifecycles, and enforcing Kubernetes RBAC with isolated namespaces.

👉 **[Click here to view the Full Lab Report & Evidence Details](Lab1/Lab1_Account_Security_and_IAM.md)**

---

## 🎯 Key Learning Highlights & Results

| Task / Domain | Security Concept | Implementation | Verification Status |
| :--- | :--- | :--- | :---: |
| **Task 1: Account Security** | Identity Baseline & Root Protection | AWS STS & LocalStack identity verification | **VERIFIED** |
| **Task 2: User & Group IAM** | Role-Based Access Control | Admin & Analyst groups with least-privilege JSON policies | **VERIFIED** |
| **Task 3: Key Lifecycle** | Credential Hygiene & Rotation | Programmatic access key generation, deactivation & deletion | **VERIFIED** |
| **Task 4: K8s Namespaces** | Multi-Tenancy Boundary | Dedicated `dev` and `prod` namespace isolation | **VERIFIED** |
| **Task 5: K8s RBAC** | Scoped Authorization | Developer Role & RoleBinding restricted to pod read-only | **VERIFIED** |

---

## 📁 Branch Structure

```text
lab1
  Lab1/
    Lab1_Account_Security_and_IAM.md
    Evidence/
```

🔗 *Return to [Main Landing Page](https://github.com/katakambing/Cloud-Security-Labs-IKB42603)*
