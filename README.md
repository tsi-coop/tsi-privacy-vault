# TSI Privacy Vault

An open-source digital safe that isolates personal and sensitive data for effortless compliance.

## Introduction

[TSI Privacy Vault: An Open Source Digital Safe for your business](https://techadvisory.substack.com/p/tsi-privacy-vault-an-open-source)

[Installation Steps](https://youtu.be/8zBjy5XQH-I)

[Entities and Utilities Configuration](https://youtu.be/Pbkf7gzgNas)

[Data Client Tour](https://youtu.be/jvI_LD-pSfQ)

[Utility Client Tour](https://youtu.be/HBa32fdSJ60)

[Court Ready Evidence](https://youtu.be/oRfr3wVTWnw)

## Installation

### Docker

1.  **Clone the repository to a separate folder**
   ```bash
   git clone https://github.com/tsi-coop/tsi-privacy-vault.git tsi-privacy-vault-eval
   ```
2. **Change directory** 
```bash
cd tsi-privacy-vault-eval
```
3. **Create .env File:**
This file stores sensitive configurations (passwords, API keys, etc.) and is NOT committed to Git. Copy from .example
```bash
cp .example .env
```
Now, edit the newly created .env file and fill in the placeholder values.

4.  **Start the TSI Privacy Vault service**
   ```bash   
   sudo docker compose up -d
   ```

## Post-Installation Steps

The system includes a pre-configured interactive tour designed for evaluators and administrators to explore the Sovereign Data Isolation capabilities.

Access the Tour: Open your browser and navigate to: http://localhost:8080/tour.

Follow the Guided Journey:

1. Environment Setup: Initialize the Sovereign Safe, define Master Keys, and establish the root hardware anchor for the vault instance.

2. Data Client: Ingest, store, and retrieve records across ID, DATA, and FILE flavors using integrated forensic hashing.

3. Utility Client: Perform handshakes to fetch authorized cryptographic assets, system keys, and SSL certificates.

4. API Technical Tour: Review technical specifications, request/response structures, and unified headers for all data flavors.

## References

[Aadhaar Vault](https://techadvisory.substack.com/p/solution-explainer-aadhaar-vault)

[Search functionality on encrypted PII data](https://techadvisory.substack.com/p/implementing-search-functionality)

## License

TSI Privacy Vault is licensed under AGPL v3 license