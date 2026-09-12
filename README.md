# IKB42603 Cloud Computing Security Essentials — Lab 6: Object Storage Security & the Data Security Lifecycle

**Student:** WAN MUHAMMAD NUR IMAN BIN WAN ISMAIL  
**Student ID:** 52215225039  
**Branch:** `lab6`  

---

## 📌 Executive Summary

This lab demonstrates Amazon S3 object storage security controls, data classification, Block Public Access guardrails, Identity vs Resource-based policy evaluation, SSE-KMS default encryption, presigned URL delegated access, S3 versioning & data remanence, lifecycle retention rules, cryptographic erasure, and advanced WORM / CSPM / Client-side encryption expansions on LocalStack.

👉 **[Click here to view the Full Lab Report & Evidence Details](Lab6/Lab6_Object_Storage_Security_and_Data_Lifecycle.md)**

---

## 🎯 Key Learning Highlights & Verification Results

| Task / Domain | Security Concept | Implementation | Verification Status |
| :--- | :--- | :--- | :---: |
| **Data Classification** | 3-Tier Classification Table | Healthcare metadata taxonomy (`public`, `internal`, `confidential`) | **VERIFIED** |
| **Task 1: Data Classification** | Tagging & Metadata | Storing public, internal & confidential objects with tags | **VERIFIED** |
| **Task 2: Archetypal Breach** | Bucket Policy Exposure | Reproducing anonymous leak with `"Principal": "*"` over HTTP | **VERIFIED** |
| **Task 3: Block Public Access** | Preventative Guardrail | Applying 4 BPA flags and least-privilege policy on `/internal/*` | **VERIFIED** |
| **Task 4: Policy Precedence** | IAM vs Bucket Policy | Proving explicit Deny overrides IAM Allow for `DataAnalyst` | **VERIFIED** |
| **Task 5: Default Encryption** | SSE-KMS at Bucket Scale | Customer-managed KMS key default encryption with `BucketKeyEnabled` | **VERIFIED** |
| **Task 6: Delegated Access** | Presigned URLs & TLS | Time-bounded access & `aws:SecureTransport` condition-key analysis | **VERIFIED** |
| **Task 7: Data Remanence** | S3 Versioning & Deletion | Demonstrating delete marker recovery & per-version permanent purge | **VERIFIED** |
| **Task 8: Retention & Erasure**| Lifecycle Rules & KMS Deletion | Automated archival & provable cryptographic erasure (`PendingDeletion`) | **VERIFIED** |
| **Expansion 1: Object Lock** | WORM Compliance Storage | Immutable audit trail in `COMPLIANCE` mode rejecting deletion | **VERIFIED** |
| **Expansion 2: CSPM Scanner** | Automated Posture Auditing | Custom shell scanner evaluating BPA, Encryption, and Versioning | **VERIFIED** |
| **Expansion 3: Client-Side Crypto**| Zero-Trust Provider Isolation | Local AES-256-CBC client encryption vs S3 ciphertext storage | **VERIFIED** |
| **Short-Answer Questions** | Q1 to Q6 Technical Analysis | In-depth cybersecurity answers covering ATT&CK, IAM logic, GDPR | **VERIFIED** |

---

## 📁 Branch Structure

```text
lab6
├── README.md
└── Lab6/
    ├── Lab6_Object_Storage_Security_and_Data_Lifecycle.md
    └── Evidence/
        ├── task1-list-objects-and-tagging.png
        ├── task2-anonymous-curl-leak.png
        ├── task3-block-public-access.png
        ├── task4-analyst-iam-setup.png
        ├── task4-identity-vs-resource-policy.png
        ├── task5-default-sse-kms-encryption.png
        ├── task6-presigned-url.png
        ├── task6-secure-transport-condition-trap.png
        ├── task7-versioning-delete-marker.png
        ├── task7-versioning-and-remanence.png
        ├── task8-lifecycle-and-kms-deletion.png
        ├── task8-final-verification-block.png
        ├── expansion-task1-object-lock-worm.png
        ├── expansion-task2-cspm-script.png
        ├── expansion-task2-cspm-audit-scanner.png
        └── expansion-task3-client-side-encryption.png
```

🔗 *Return to [Main Landing Page](https://github.com/katakambing/Cloud-Security-Labs-IKB42603)*
