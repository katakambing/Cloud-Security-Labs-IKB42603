# IKB42603 Cloud Computing Security Essentials — Lab 3: Data Protection — Encryption & Key Management

**Student:** WAN MUHAMMAD NUR IMAN BIN WAN ISMAIL  
**Student ID:** 52215225039  
**Branch:** `lab3`  

---

## 📌 Executive Summary

This lab demonstrates end-to-end data protection across the cloud data lifecycle. It implements symmetric (AES-256) data-at-rest encryption, asymmetric (RSA-2048) signatures, TLS in-transit encryption, two-tier envelope encryption using AWS KMS (via LocalStack), per-tenant master key isolation, provable cryptographic erasure, and tamper-evident SHA-256 hash chains.

👉 **[Click here to view the Full Lab Report & Evidence Details](Lab3/Lab3_Encryption_and_Key_Management.md)**

---

## 🎯 Key Learning Highlights & Results

| Task / Domain | Security Concept | Implementation | Verification Status |
| :--- | :--- | :--- | :---: |
| **Task 1: Data at Rest** | Symmetric Encryption | AES-256-CBC with PBKDF2 salt derivation | **VERIFIED** |
| **Task 2: Signatures** | Authenticity & Non-Repudiation | RSA-2048 key pair, public encryption & signature verification | **VERIFIED** |
| **Task 3: Data in Transit** | Channel Confidentiality | TLS over HTTPS via containerized Nginx on port 8443 | **VERIFIED** |
| **Task 4: Envelope Encryption**| Two-Tier Key Architecture | KMS CMK wrapping DEK; plaintext DEK purged from memory | **VERIFIED** |
| **Task 5: Crypto-Erasure** | Provable Cloud Deletion | Tenant master key deletion rendering ciphertext unrecoverable | **VERIFIED** |
| **Task 6: Hash Chaining** | Tamper-Evident Audit Trails | SHA-256 recursive log chaining & avalanche effect | **VERIFIED** |

---

## 📁 Branch Structure

```text
lab3
  Lab3/
    Lab3_Encryption_and_Key_Management.md
    Evidence/
```

🔗 *Return to [Main Landing Page](https://github.com/katakambing/Cloud-Security-Labs-IKB42603)*
