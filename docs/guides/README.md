# Guides: Where to Start

Read these in order the first time. Each guide says what comes before it and what comes
next. Later, use the table as an index.

## 1. Understand the vault

The vault sits between your applications and your personal data. Your application sends a
value and gets back an opaque **reference key**. The vault encrypts the value with its own
key, keeps it, and records every touch. Your application never holds the data.

The words you will meet:

| Term | Meaning |
|---|---|
| **Entity** | A named kind of value you define once, such as `PAN` or `KYC_SCAN`, with the rules the vault enforces |
| **Flavour** | How an entity is handled: `ID` (tokenized), `DATA` (encrypted and searchable) or `FILE` (encrypted binary) |
| **Reference key** | The opaque ID your application keeps instead of the value |
| **Principal** | The person a record belongs to, identified by an opaque `principal_id` you choose. Erasure works on a principal |
| **API key** | The identity of one application, with read and write grants per entity |
| **Utility** | A credential or certificate held by the vault, such as a third-party API key |
| **Key anchor** | Where the root key lives (`LOCAL` or AWS KMS). It wraps the keys that protect your data, and never sees the data |

Every value is encrypted with its own data key, and the root key protects those. That is
the whole security model. The [architecture document](../design/architecture.md) explains
it with diagrams, and you do not need it to follow the guides below.

## 2. The path

| Step | Do this | Guide |
|---|---|---|
| **1. Install** | Start the vault and create the administrator | [Quick Start](../../README.md#quick-start), then the interactive tour |
| **2. Configure** | Define your entities, create an API key per application and grant it access | [Entities, API Keys and Permissions](entity-management.md) |
| | Store credentials and certificates for your workflows (optional) | [Utilities](utilities-management.md) |
| **3. Integrate** | Store, fetch, search and erase from your application | [API Integration](api-integration.md) |
| **4. Operate** | Handle a data erasure request, set retention and legal holds | [Erasure Management](erasure-management.md) |
| | Control admin roles and prove the audit log is untampered | [Audit and Access Control](audit-and-access-control.md) |
| **5. Go to production** | Move the root key into a managed AWS KMS key | [AWS KMS Configuration](aws-kms-configuration.md) |
| | Keep encrypted files in AWS S3 | [AWS S3 Configuration](aws-s3-configuration.md) |

Steps 1 to 3 get a working integration. Step 4 is what you run day to day. Step 5 is for
when you leave evaluation. You can do the two guides in step 5 in either order, and the
vault works without them.

## 3. Questions each guide answers

| Question | Guide |
|---|---|
| What can I store, and what does the vault check? | [Entities](entity-management.md#3-create-an-entity) |
| Who may read or write which data? | [Entities, section 7](entity-management.md#7-grant-permissions) |
| What do I send, and what errors do I handle? | [API Integration](api-integration.md) |
| A person asked for their data to be erased | [Erasure Management](erasure-management.md#5-handle-an-erasure-request) |
| Can I prove nobody edited the audit log? | [Audit and Access Control](audit-and-access-control.md#2-tamper-evident-audit-log) |
| Where does the root key live, and can I move it? | [AWS KMS](aws-kms-configuration.md) |
| Where do files live? | [AWS S3](aws-s3-configuration.md) |
| Where do I keep a third-party API key? | [Utilities](utilities-management.md) |
