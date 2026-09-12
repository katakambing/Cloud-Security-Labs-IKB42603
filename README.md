# IKB42603 Cloud Computing Security Essentials — Lab 6: Object Storage Security & the Data Security Lifecycle

**Student:** WAN MUHAMMAD NUR IMAN BIN WAN ISMAIL  
**Student ID:** 52215225039  
**Branch:** `lab6`  

---

## 📌 Executive Summary

This lab demonstrates Amazon S3 object storage security controls, data classification, Block Public Access guardrails, Identity vs Resource-based policy evaluation, SSE-KMS default encryption, presigned URL delegated access, S3 versioning & data remanence, lifecycle retention rules, and cryptographic erasure on LocalStack.

👉 **[Click here to view the Full Lab Report & Evidence Details](Lab6/Lab6_Object_Storage_Security_and_Data_Lifecycle.md)**

---

## 🎯 Key Learning Highlights & Results

| Task / Domain | Security Concept | Implementation | Verification Status |
| :--- | :--- | :--- | :---: |
| **Task 1: Data Classification** | Tagging & Classification | Storing public, internal & confidential objects | In Progress |
| **Task 2: Archetypal Breach** | Bucket Policy Exposure | Reproducing anonymous leak with `"Principal": "*"` | In Progress |
| **Task 3: Block Public Access** | Preventative Guardrail | Applying 4 BPA flags and least-privilege policy | In Progress |
| **Task 4: Policy Precedence** | IAM vs Bucket Policy | Proving explicit Deny overrides IAM Allow | In Progress |
| **Task 5: Default Encryption** | SSE-KMS at Bucket Scale | KMS customer-managed key default encryption | In Progress |
| **Task 6: Delegated Access** | Presigned URLs & TLS | Time-bounded access & `aws:SecureTransport` | In Progress |
| **Task 7: Data Remanence** | S3 Versioning & Deletion | Demonstrating delete marker recovery & per-version purge | In Progress |
| **Task 8: Retention & Erasure**| Lifecycle Rules & KMS Deletion | Automated archival & cryptographic erasure | In Progress |

---

## 📁 Branch Structure

```text
lab6
  Lab6/
    Lab6_Object_Storage_Security_and_Data_Lifecycle.md
    Evidence/
```

🔗 *Return to [Main Landing Page](https://github.com/katakambing/Cloud-Security-Labs-IKB42603)*
