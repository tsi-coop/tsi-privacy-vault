# TSI Privacy Vault

An open-source digital safe that isolates personal and sensitive data for effortless compliance.

## Introduction

Storing sensitive details like IDs, Personal Files, or Private Contracts inside everyday business apps is like leaving your most valuable belongings scattered in every room of a house. Just as we use a physical safe to isolate and protect our most valuable physical assets, we must apply that same thinking to our digital world.

TSI Privacy Vault allows you to move the personal and sensitive data from business applications into an isolated & hardened environment. The solution is designed to manage Digital IDs (Abha ID, PAN, Voter ID), Personal Data (Name, Address, Medical Records), and Sensitive Files (Contracts, X-ray images). In addition, it provides a utilities repository to manage API Keys, service credentials, and digital certificates.

### Key Features and Capabilities

- Three Data Flavours: Specialized handling for IDs (tokenization), DATA (field-level encryption), and FILES (secure binary storage).
- Encrypted Search Capability: Enables secure discovery of PII through a Deterministic Blind Index. This allows for full-name, segment, and 3-character-prefix searches without decrypting the underlying data or exposing plaintext keywords to the database.
- Utilities Management: A single point of control for managing the lifecycle of API keys and SSL certificates across your entire organisation.
- Forensic Anchoring: Every access request is cryptographically linked to a specific user and a physical machine ID, creating an immutable audit trail.
- Automated Governance: Built-in alerts for certificate expiries and tools for mandatory key rotation.

### Benefits: Security and Sovereignty

- Data Sovereignty: By using this vault, you maintain total ownership and control over your encryption keys and data residency, fulfilling the core requirements of the DPDPA.
- Reduced Attack Surface: Since sensitive secrets are no longer scattered across various app configurations, a breach in one application doesn't compromise your entire system.
- Compliance Ready: The Vault automatically generates the forensic evidence required for BSA audits, proving exactly who accessed what data and from which device.
- Transparency: Being open source means your security team can inspect every line of code.

## Installation

### Docker

1.  Clone the repository to a separate folder
   ```bash
   git clone https://github.com/tsi-coop/tsi-privacy-vault.git tsi-privacy-vault-eval
   ```
2. Change directory
```bash
cd tsi-privacy-vault-eval
```
3. Create .env File:
This file stores sensitive configurations (passwords, API keys, etc.) and is NOT committed to Git. Copy from .example
```bash
cp .example .env
```
Now, edit the newly created .env file and fill in the placeholder values.

4.  Start the TSI Privacy Vault service
   ```bash   
   sudo docker compose up -d
   ```

## Post-Installation Steps

The system includes a pre-configured interactive tour designed for evaluators and administrators to explore the Sovereign Data Isolation capabilities.

Access the Tour: Open your browser and navigate to: http://localhost:8081/tour.

Watch the [Installation Steps](https://youtu.be/8zBjy5XQH-I) walkthrough for a video tour of the steps above.

Follow the Guided Journey:

1. Environment Setup: Initialize the Sovereign Safe, define Master Keys, and establish the root hardware anchor for the vault instance. Watch the [Entities and Utilities Configuration](https://youtu.be/Pbkf7gzgNas) walkthrough.

2. Data Client: Ingest, store, and retrieve records across ID, DATA, and FILE flavors using integrated forensic hashing. Watch the [Data Client Tour](https://youtu.be/jvI_LD-pSfQ) walkthrough.

3. Utility Client: Perform handshakes to fetch authorized cryptographic assets, system keys, and SSL certificates. Watch the [Utility Client Tour](https://youtu.be/HBa32fdSJ60) walkthrough.

4. API Technical Tour: Review technical specifications, request/response structures, and unified headers for all data flavors.

5. Court Ready Evidence: Review the forensic audit trail and evidence generation capabilities. Watch the [Court Ready Evidence](https://youtu.be/oRfr3wVTWnw) walkthrough.

## Key Management: LOCAL vs AWS KMS

Every record's Data Encryption Key (DEK) is wrapped by a root key anchor.

Out of the box, with no extra setup, the vault runs on the LOCAL anchor -
the Master Key in your `.env` file. Note that `.env` isn't generated
automatically; it's created once, during installation (step 3 above), by
copying the provided template:

```bash
cp .example .env
```

then editing the placeholder values. This is what the Docker install above
gives you, and it's all you need to evaluate the vault or run it fully
on-prem/air-gapped.

AWS KMS is opt-in: a separate, one-time migration you run later if/when
you want your root key held in an AWS-managed HSM instead of an env var. You
don't need to touch AWS at all to use the vault.

| | LOCAL (default) | AWS KMS (opt-in) |
|---|---|---|
| Root key | `TSI_PRIVACY_VAULT_MASTER_KEY` env var (SHA-256'd, held in process memory) | AWS KMS Customer Managed Key (CMK) - never leaves AWS |
| Best for | Local evaluation, air-gapped/on-prem deployments | Production deployments wanting cloud HSM-backed key custody, automatic rotation, and CloudTrail audit logging |
| Setup | Works out of the box via `.env` | One-time setup: create the CMK, attach a least-privilege IAM policy, then activate the anchor and re-wrap existing records from the admin console's Key Anchor page |

Payload ciphertext is always decrypted locally either way - AWS only ever
sees a wrapped ~48-byte data key, never your data.

Switching anchors is a two-step, resumable migration (activate, then
re-wrap) and existing records stay readable throughout. Full walkthrough,
IAM policy, and troubleshooting: [docs/aws-kms-configuration.md](docs/aws-kms-configuration.md). Future roadmap includes support for GCP KMS, Azure Key Vault and Sovereign multi-custodian setup via Shamir's Secret Sharing).

### What is "re-wrap", and how do I run it?

Every record's payload is encrypted with its own one-time Data Encryption Key
(DEK), and that DEK is itself encrypted ("wrapped") by whichever root key
anchor was active when the record was written - LOCAL at first, AWS KMS once
you switch. Re-wrap is the migration step that unwraps each record's DEK
under the old anchor and re-wraps it under the new one, so old records
become readable under the new anchor too. It only ever touches that small
(~48-byte) wrapped key - your actual data (the payload ciphertext) is never
re-encrypted, so re-wrapping a large vault is cheap.

Why a separate step at all, instead of doing it automatically? Activating a
new anchor only affects *new* writes going forward; existing records still
point at the old anchor until you explicitly migrate them. Re-wrap is what
performs that migration, in batches, while the vault stays online.

How to run it, after you've activated the AWS KMS anchor (see
[docs/aws-kms-configuration.md](docs/aws-kms-configuration.md) steps 1-6):

1. Open the admin console's Key Anchor page.
2. Find the Rewrap Data Keys card. It shows how many records are still
   pending (wrapped under a non-active key version).
3. Click Run Batch (default batch size 500). Each click migrates one
   batch and updates the pending count.
4. Repeat until Remaining Entities and Remaining Utilities both read
   `0`. At that point the old key version is automatically retired.

That's it - the vault is now fully on the new anchor. The same flow is
available via the `rewrap_data_keys` admin API call if you'd rather script it.

### Common ways to get it wrong

- Don't change `TSI_PRIVACY_VAULT_NODE_ID` between activating the anchor
  and finishing the re-wrap (or ever, really, once you're on AWS KMS).
  AWS KMS calls bind each wrapped key to an encryption context derived from
  this value, and the running container caches that value for its whole
  lifetime. Change it mid-migration and you'll get ciphertext bound to one
  context while the app expects another - surfacing later as
  `InvalidCiphertextException` on fetch. If you genuinely need to rename the
  node, treat it as a brand-new anchor migration (restore the old value,
  finish migrating, only then rename), not a quick `.env` edit.
- `vault_utilities` rows also carry a `machine_id` "hardware anchor",
  checked independently of the KMS context, on every fetch. Re-wrap keeps
  this in sync with the current node identity automatically. If you hit a
  `Hardware anchor mismatch` 403 even though KMS decryption itself is fine,
  this column is stale - it can happen on older builds, or if a record was
  never re-wrapped after a node rename.
- Run re-wrap to completion in one sitting right after activation, so
  every row ends up consistent. Before removing
  `TSI_PRIVACY_VAULT_MASTER_KEY` from `.env` for good, confirm
  `Remaining Entities/Utilities` are both `0` and that a pre-migration record
  still fetches successfully.

## Release Notes

[Changelog](CHANGELOG.md)

## License & Contributions

This project is fully open-source and distributed under the Apache 2.0 License. You are completely free to fork, modify, and customize the codebase to fit your specific technical or enterprise needs without any restriction.

### Contributing Back to the Main Project
If you have built an optimization, bug fix, or feature extension that you believe would add value to the core platform, we would love to review it. To ensure the main repository remains highly stable and securely managed, direct commits to the `main` branch are restricted.

If you wish to give back your changes to the project, please follow this process:

* Email the Repository Owner: Send a brief summary of your modifications and a link to your code branch directly to admin@tsicoop.org.

Every contribution is manually evaluated for architectural alignment, readability, and long-term maintenance impact before integration. Thank you for respecting this workflow and helping us maintain a clean, resilient core!

## Further Reading

[Aadhaar Vault](https://techadvisory.substack.com/p/solution-explainer-aadhaar-vault)

[Search functionality on encrypted PII data](https://techadvisory.substack.com/p/implementing-search-functionality)
