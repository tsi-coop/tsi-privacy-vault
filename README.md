# TSI Privacy Vault

An open-source digital safe that isolates personal and sensitive data for effortless compliance.

Read the [launch post](https://techadvisory.substack.com/p/tsi-privacy-vault-an-open-source) for the background and the thinking behind it.

## Why Privacy Vault

Just as a physical safe secures valuable assets, TSI Privacy Vault keeps personal and sensitive data out of your business applications: IDs, personal records, contracts, scans. Your applications hold an opaque reference. The vault holds the data, encrypted, and records every touch.

If you have ever had to answer "where does this person's data live?", "who has read it?" or "can you delete it?", this is built for you.

## Key Features

- **Three kinds of data.** IDs (PAN, Aadhaar, Voter ID), personal data (names, addresses, records) and sensitive files (contracts, X-rays).
- **Search without decrypting.** Find a record by a name, a word or an identifier through a blind index. The vault never opens the data to look.
- **Erasure on request.** Erase everything about one person in a single request, while the records you are legally required to keep stay readable.
- **Your choice of storage.** Keep encrypted files in the database, or in AWS S3 or an S3-compatible store such as MinIO.
- **Your choice of key custody.** Keep the root key in your own environment, or in a managed AWS KMS key.
- **Court-ready evidence.** Every request is anchored to a user and a device, giving you an audit trail you can stand behind under BSA Section 63.
- **A utilities repository** for API keys, service credentials and certificates.

In short: a smaller breach surface, a clean answer to DPDPA erasure requests, and tamper-proof evidence.

## Quick Start

You need Docker and a terminal.

1. Clone the repository:
   ```bash
   git clone https://github.com/tsi-coop/tsi-privacy-vault.git tsi-privacy-vault-eval
   cd tsi-privacy-vault-eval
   ```
2. Create your `.env` from the template, and give it a setup token:
   ```bash
   cp .example .env
   sed -i '/^TSI_PRIVACY_VAULT_BOOTSTRAP_TOKEN=/d' .env
   printf '\nTSI_PRIVACY_VAULT_BOOTSTRAP_TOKEN=%s\n' "$(openssl rand -hex 32)" >> .env
   ```
   Review the placeholder values in `.env` while you are there. The setup token is a
   mandatory security step: the first-run page asks for it before it creates the
   administrator account. Remove it from `.env` once setup is done.
3. Start the vault:
   ```bash
   sudo docker compose up -d
   ```
4. Open <http://localhost:8081/init.html>, enter the setup token and create your administrator account.
5. Open the interactive tour at <http://localhost:8081/tour> and follow the guided journey.

Prefer to watch first? The [installation walkthrough](https://youtu.be/8zBjy5XQH-I) covers these steps.

## Video Tour

The tour is a hands-on walk through the vault, with no code to write.

| Step | You will | Video |
|---|---|---|
| Environment setup | Create the administrator, then define entities and utilities | [Watch](https://youtu.be/Pbkf7gzgNas) |
| Data client | Store, retrieve and search IDs, data and files | [Watch](https://youtu.be/jvI_LD-pSfQ) |
| Utility client | Fetch authorized keys and certificates | [Watch](https://youtu.be/HBa32fdSJ60) |
| API tour | See every request and response | |
| Court-ready evidence | Review the audit trail and evidence | [Watch](https://youtu.be/oRfr3wVTWnw) |

## Developer Guides

Pick what you want to do next.

| I want to... | Go to |
|---|---|
| Call the vault from my application | [API integration guide](docs/guides/api-integration.md) |
| Run scripts that exercise store, fetch, search and erasure | [Examples](examples/README.md) |
| Restrict admin roles, and verify the audit log is untampered | [Audit and access control guide](docs/guides/audit-and-access-control.md) |
| Handle a data erasure request, and set retention | [Erasure management guide](docs/guides/erasure-management.md) |
| Keep files in S3 or MinIO | [AWS S3 configuration guide](docs/guides/aws-s3-configuration.md) |
| Hold the root key in AWS KMS | [AWS KMS configuration guide](docs/guides/aws-kms-configuration.md) |
| Understand how it works and where it is going | [Architecture and roadmap](docs/design/architecture.md) |

The architecture document has the two diagrams that explain most of it:
[envelope encryption](docs/design/images/envelope-encryption-diagram.png) and
[blind index search](docs/design/images/blind-index-search-diagram.png).

## Key Management

The vault encrypts every record with its own key, and a root key protects those. You choose where the root key lives, and you can change your mind later without re-encrypting your data.

- **Sovereign.** For on-prem and air-gapped environments. The root key stays in your own environment, and a self-hosted OpenBao integration is planned.
- **Cloud.** For deployments that want a managed, HSM-backed root key. AWS KMS is supported today, and Google Cloud KMS and Azure Key Vault will follow on demand.

The root key provider never sees your data, and the vault never stores the root key in its database. The [architecture document](docs/design/architecture.md) explains the model and the [AWS KMS guide](docs/guides/aws-kms-configuration.md) walks through the move to a managed key.

## Testing and releases

- [Test cases, load test and runners](tests/README.md)
- [Changelog](CHANGELOG.md)

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
