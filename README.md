# TSI Privacy Vault

An open-source digital safe that isolates personal and sensitive data for effortless compliance.

## Introduction

Just as a physical safe secures valuable assets, TSI Privacy Vault isolates personal and sensitive data from business applications, including IDs, personal files, contracts, etc.

### Key Features

- Three Data Flavours: IDs (ABHA ID, PAN, Voter ID), Personal Data (Name, Address, Medical Records), and Sensitive Files (Contracts, X-ray images)
- Encrypted Search Capability: Creates a Deterministic Blind Index. It enables text search without decrypting the underlying data.
- Utilities: Provides a utilities repository to manage API Keys, service credentials, and digital certificates.
- Legal Evidence: Every request to the vault is cryptographically anchored to a user and a device, creating an immutable audit trail.

The key benefits of the sovereign vault include reducing the breach surface, supporting DPDPA compliance by easily fulfilling erasure requests, and maintaining tamper-proof evidence for BSA Section 63.

The vault supports two tracks. The Sovereign track uses a local master key and suits on-prem and air-gapped environments. The Cloud track uses AWS Key Management Service. Both are supported today. Next, the Sovereign track adds Shamir split keys, and the Cloud track adds Google Cloud KMS and Azure Key Vault on demand.

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

Generate a random setup token and write it into `.env`:
```bash
sed -i "s|^TSI_PRIVACY_VAULT_BOOTSTRAP_TOKEN=.*|TSI_PRIVACY_VAULT_BOOTSTRAP_TOKEN=$(openssl rand -hex 32)|" .env
```
This is a mandatory security step. The first-run setup page (`/init.html`) asks for this value before it creates the administrator account, and setup is refused if it is not set. Remove it from `.env` once setup is done.

4.  Start the TSI Privacy Vault service
   ```bash   
   sudo docker compose up -d
   ```

## Post-Installation Steps

The system includes a pre-configured interactive tour designed for evaluators and administrators to explore the Sovereign Data Isolation capabilities.

Access the Tour: Open your browser and navigate to: http://localhost:8081/tour.

Watch the [Installation Steps](https://youtu.be/8zBjy5XQH-I) walkthrough for a video tour of the steps above.

Follow the Guided Journey:

1. Environment Setup: Open `/init.html`, enter the `TSI_PRIVACY_VAULT_BOOTSTRAP_TOKEN` value from `.env` as the Setup Token, and create the administrator account. Then initialize the Sovereign Safe, define Master Keys, and establish the root hardware anchor for the vault instance. Watch the [Entities and Utilities Configuration](https://youtu.be/Pbkf7gzgNas) walkthrough.

2. Data Client: Ingest, store, and retrieve records across ID, DATA, and FILE flavors using integrated forensic hashing. Watch the [Data Client Tour](https://youtu.be/jvI_LD-pSfQ) walkthrough.

3. Utility Client: Perform handshakes to fetch authorized cryptographic assets, system keys, and SSL certificates. Watch the [Utility Client Tour](https://youtu.be/HBa32fdSJ60) walkthrough.

4. API Technical Tour: Review technical specifications, request/response structures, and unified headers for all data flavors.

5. Court Ready Evidence: Review the forensic audit trail and evidence generation capabilities. Watch the [Court Ready Evidence](https://youtu.be/oRfr3wVTWnw) walkthrough.

## Architecture and Key Management

Every record is encrypted with its own Data Encryption Key (DEK), and that key is wrapped by a root key anchor. Out of the box the vault runs on the **LOCAL** anchor, the master key in your `.env` file, which is all you need for evaluation or fully on-prem and air-gapped use. **AWS KMS** is an opt-in, resumable migration (activate the anchor, then re-wrap existing records) for deployments that want the root key held in an AWS-managed HSM. Payload data is always encrypted and decrypted locally. AWS only ever sees a wrapped data key.

- [Architecture and roadmap](docs/architecture.md): envelope encryption, blind index search, LOCAL vs AWS KMS, what re-wrap is, and the plan for GCP KMS, Azure Key Vault and Shamir's Secret Sharing.
- [AWS KMS configuration guide](docs/aws-kms-configuration.md): CMK setup, IAM policy, activation, re-wrap, common mistakes and troubleshooting.

## Testing

[Functional test cases and the JMeter load test](tests/README.md): key management test cases (LOCAL and AWS KMS) and a data plane load test with tunable concurrency.

## Release Notes

[Changelog](CHANGELOG.md)

## License & Contributions

This project is fully open-source and distributed under the Apache 2.0 License. You are completely free to fork, modify, and customize the codebase to fit your specific technical or enterprise needs without any restriction.

### Contributing Back to the Main Project
See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) for reporting vulnerabilities, and the [Code of Conduct](CODE_OF_CONDUCT.md).

If you have built an optimization, bug fix, or feature extension that you believe would add value to the core platform, we would love to review it. To ensure the main repository remains highly stable and securely managed, direct commits to the `main` branch are restricted.

If you wish to give back your changes to the project, please follow this process:

* Email the Repository Owner: Send a brief summary of your modifications and a link to your code branch directly to admin@tsicoop.org.

Every contribution is manually evaluated for architectural alignment, readability, and long-term maintenance impact before integration. Thank you for respecting this workflow and helping us maintain a clean, resilient core!

## Further Reading

[Aadhaar Vault](https://techadvisory.substack.com/p/solution-explainer-aadhaar-vault)

[Search functionality on encrypted PII data](https://techadvisory.substack.com/p/implementing-search-functionality)
