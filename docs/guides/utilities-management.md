# Utilities Guide: Credentials and Certificates

How to keep the few credentials your workflows depend on, such as third-party API keys,
service passwords and certificates, in the vault, and how an application reads them.
Utilities use the same envelope encryption, per-key permissions and audit log as personal
data, so there is one place to control and review both.

Before this: [Entities, API Keys and Permissions](entity-management.md), because a utility
is granted to an application the same way an entity is. Next: [API Integration](api-integration.md).

Related guides:
[API Integration](api-integration.md) for the client calls,
[Audit and Access Control](audit-and-access-control.md) for roles and the audit chain,
and the [AWS KMS Configuration Guide](aws-kms-configuration.md) for the root key.

---

## 1. What utilities are, and how they relate to the key anchor

These are two different layers:

- **The key anchor** (`LOCAL`, AWS KMS, and later OpenBao) holds the root key. Its only
  job is to wrap and unwrap data keys. It never stores your secrets or your data.
- **Utilities** are secrets stored by the vault. Each one is encrypted with its own data
  key, and that data key is wrapped by the anchor. The ciphertext lives in the
  `vault_utilities` table in PostgreSQL.

So a utility is not "stored in KMS". KMS protects the key that protects the secret.

## 2. When to use them

Utilities make the most sense when the vault already guards your personal data and you
want one audited place to hold the few credentials those workflows depend on.

What you get:

- **One control plane.** The same per-key read permission, the same role checks and the
  same hash-chained audit log as personal data. An application's API key can be granted
  read on exactly one utility.
- **Anchor portability.** The secrets are handled the same way whichever anchor is
  active. `rewrap_data_keys` re-wraps utilities together with the data
  (`Remaining Utilities` in the KMS guide).
- **Ciphertext only at rest.** A database dump has nothing readable without the anchor.
- **Fewer moving parts.** In an on-prem or sovereign setup you do not need a separate
  secrets manager next to the vault.

What it is not:

- It is not a dynamic secrets engine. There are no leases, no automatic rotation and no
  native integrations like those in AWS Secrets Manager or the OpenBao KV engine.
- Resolving a utility **returns the plaintext** to the caller. The vault protects the
  secret at rest and controls who may fetch it. It cannot stop a compromised caller from
  using what it fetched.
- If you already run a secrets manager well and nothing else in your design needs the
  vault, a utility adds little.

## 3. Enroll a utility (administrator)

In the admin console, open **Utilities** and choose **Enroll New Utility**. You give it:

| Field | Meaning |
|---|---|
| Label | A unique name. **This is the identifier applications use to resolve it**, so choose it deliberately, for example `PAYMENT_GATEWAY_KEY` |
| Category | `KEYS`, `CERT` or `SHARED_KEYS` |
| Payload | The secret itself. It is encrypted before it is written |

The console shows the utility ID. The label cannot be reused.

Enrolling needs the `SYSTEM_ADMIN` role. Other roles can list utilities but not change them.

To change a secret, use **Rotate** on the utility and give the new payload. The vault
generates a new data key, re-encrypts the payload and records the key version. The label
and the permissions stay the same, so applications are unaffected.

## 4. Grant an application access

On the **API Keys** page, add a permission for the application's key (the key itself is
created as described in [Entities, API Keys and Permissions](entity-management.md#6-create-an-api-key-for-each-application)):

1. Choose resource type **UTILITY**.
2. Set the resource to the utility's **label**.
3. Grant **read**.

A key sees and resolves only the utilities it has been granted. Grant the narrowest set
each application needs.

## 5. Resolve a utility (application)

Both calls use the normal client endpoint and headers from the
[API Integration guide](api-integration.md#2-connection-and-authentication).

List what the key may use:

```json
{ "_func": "get_authorized_utilities" }
```

Resolve one by its label:

```bash
curl -s -X POST "$BASE_URL/api/client/vault" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" -H "X-API-Secret: $API_SECRET" \
  -d '{"_func":"resolve_utility","utility_id":"PAYMENT_GATEWAY_KEY"}'
```

```json
{ "success": true, "value": "the-secret-value", "id": "PAYMENT_GATEWAY_KEY" }
```

Note that `utility_id` in this call is the **label**, not the UUID.

| Status | Meaning |
|---|---|
| `400` | `utility_id` is missing |
| `401` | Wrong or missing API key or secret |
| `403` | The key has no read grant on that label, or no active utility has that label (the two look the same on purpose), or this node's machine ID differs from the utility's (section 7) |
| `503` | The key anchor is unavailable. The vault fails closed. Retry with backoff |

Fetch the value when you need it and keep it in memory. Do not write it to logs, config
files or your own database.

## 6. Audit

Every use of a utility is written to `event_log`, the same hash-chained log as personal
data, so editing or removing a row is detected. Run `verify_audit_chain` as described in
the [Audit and Access Control guide](audit-and-access-control.md).

| Operation | Written as | Actor |
|---|---|---|
| Application resolves a utility | `RESOLVE:<label>` | `VAULT:<api key>` |
| Administrator enrolls | `UTILITY_ENROLL:<label>` | `ADMIN:<user>` |
| Administrator checks out the plaintext | `UTILITY_CHECKOUT:<label>` | `ADMIN:<user>` |
| Administrator rotates | `UTILITY_ROTATE:<label>` | `ADMIN:<user>` |

Each row carries the client IP, user agent, the node's machine ID, the utility reference
and the outcome: `SUCCESS`, `DENIED` or `ERROR`. A refusal records its reason, such as
`hardware anchor mismatch`. Admin calls refused for a missing role are logged too. The
secret value is never written to the log.

## 7. The machine binding

Each utility records the `machine_id` of the node that enrolled or last rotated it. Both
the admin `checkout` and the client `resolve_utility` refuse on any other node with `403`
"Hardware anchor mismatch", and log it as `DENIED`.

- **Set `TSI_PRIVACY_VAULT_NODE_ID`.** The machine ID comes from that variable first, then
  from `/etc/machine-id`. Without a stable value, a rebuilt container or a new host reads
  as a different machine and every utility refuses.
- **Several nodes need the same ID.** If more than one vault node serves the same
  database, give them the same `TSI_PRIVACY_VAULT_NODE_ID`, or utilities enrolled on one
  node will be refused on the others.
- **Moving a utility to a new node.** Rotate it on that node. Rotating records the new
  machine ID.
- **It is a second check, not the main protection.** What protects a copied database is
  the key anchor: without access to the root key, the data keys cannot be unwrapped. The
  machine binding adds a node check on top, and it only applies where the application
  runs the vault's own code.

Other limits:

- **Rotation is manual.** Rotating a utility changes the vault's copy only. You must also
  change the credential at the system that issued it.
- **Back up the anchor.** Utilities are unreadable without the root key, exactly like
  personal data.
- **An audit failure does not block the call.** If the log write fails, the failure goes
  to the application log (`CRITICAL: ... audit logging failed`) and the call still
  completes. Watch for it.

## 8. Checklist

- [ ] Each application has its own API key, with read on only the utilities it needs.
- [ ] Labels are meaningful and stable. Applications depend on them.
- [ ] Secrets are fetched at use and are never logged or persisted by the caller.
- [ ] You rotate credentials at the source and in the vault together.
- [ ] You review `RESOLVE` and `UTILITY_*` events, especially `DENIED`, in the audit log.
- [ ] `TSI_PRIVACY_VAULT_NODE_ID` is set and identical on every node that shares the database.
