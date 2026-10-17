# Entities, API Keys and Permissions Guide

How to decide what your vault will hold and who may use it. You define each kind of
value once, as an **entity**. You then create an **API key** for each application and
grant it read and write on the entities it needs. Everything the data plane does,
store, fetch, search and erase, is checked against these two things.

Do this after the vault is installed and before you write any application code.
Next: [API Integration](api-integration.md). Related:
[Utilities](utilities-management.md) for credentials, and
[Erasure Management](erasure-management.md) for the policy hold.

---

## 1. The model

| Term | What it is |
|---|---|
| **Entity** | A named kind of value, such as `PAN`, `HOME_ADDR` or `KYC_SCAN`. It carries the rules the vault enforces on every store |
| **Flavour** | How the vault treats the value: `ID`, `DATA` or `FILE` |
| **API key** | The identity of one application. A key ID and a secret |
| **Permission** | A grant of **read** and/or **write** from one key on one entity (or one utility) |

An entity is a type, not a record. `PAN` is the entity, and each PAN you store is a
record with its own reference key.

## 2. Plan your entities

Decide these before you create anything:

1. **One entity per kind of value.** Do not put an address and a phone number in one
   entity. Rules, access and retention are set per entity, so each kind that differs in
   any of them should be its own.
2. **Pick the flavour:**

   | Flavour | Use for | Handling |
   |---|---|---|
   | `ID` | Identifiers: PAN, Aadhaar, Voter ID | Tokenized. You get a `reference_key`, and a hash lets you look it up by value |
   | `DATA` | Names, addresses, medical text | Field-level encryption, with a blind index for search |
   | `FILE` | Contracts, scans, images | Encrypted binary. Kept in PostgreSQL or [AWS S3](aws-s3-configuration.md) |

3. **Set the rules the vault should enforce:** a regex for `ID` and `DATA`, allowed MIME
   types and a size limit for `FILE`.
4. **Agree the retention with your compliance team.** Whether records of this entity must
   be kept for a period even if the person asks for erasure.

## 3. Create an entity

In the admin console, open **Entities** and choose to add one. Creating and editing needs
the `SYSTEM_ADMIN` role.

| Field | Required | Rules |
|---|---|---|
| Entity Code | yes | 1 to 50 characters: letters, digits, underscore or hyphen. Applications send this as `entityName`. **It cannot be changed afterwards** |
| Display Name | yes | Shown in the console |
| Entity Flavor | yes | `ID`, `DATA` or `FILE` |
| Validation Regex | no | `ID` and `DATA` only. Must be a valid regular expression |
| Max Size in KB | no | A positive whole number. Applies to the content sent |
| Accepted MIME Types | **yes for `FILE`** | `FILE` only. Comma separated `type/subtype`, such as `application/pdf, image/*` |
| Policy hold in days | no | Whole number from 0 to 36500. Empty means no hold. See [Erasure Management](erasure-management.md#3-set-a-policy-hold) |

A regex on a `FILE`, or MIME types on an `ID` or `DATA`, are refused with `400` and the
reason. The form only shows the fields that apply to the chosen flavour.

### Worked example

| Entity code | Flavour | Rules | Policy hold |
|---|---|---|---|
| `PAN` | `ID` | Regex `^[A-Z]{5}[0-9]{4}[A-Z]$` | 1825 days |
| `HOME_ADDR` | `DATA` | Max 4 KB | none |
| `KYC_SCAN` | `FILE` | `application/pdf, image/*`, max 2048 KB | 1825 days |

The same thing through the admin API, after you sign in:

```bash
curl -s -X POST "$BASE_URL/api/admin/entity" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"_func":"create_entity","entity_code":"PAN","entity_name":"PAN card number",
       "flavor":"ID","validation_regex":"^[A-Z]{5}[0-9]{4}[A-Z]$","retain_days":1825,"active":true}'
```

`get_all_entities` lists them. A duplicate code returns `409`.

## 4. What the vault enforces on each store

Every `store_data` call is checked against the entity, in this order. The first failure
ends the request.

| Check | Failure |
|---|---|
| The key may write this entity | `403` |
| The entity exists and is active | `404` "Unknown or inactive entity" |
| `entityType` matches the entity's flavour | `400` |
| Size is within `max_size_kb` | `413` |
| For `FILE`: a file name, Base64 content and an allowed MIME type | `400`, `415` |
| For `ID` and `DATA`: the value matches the regex | `422` |

The full list and the error handling are in the [API Integration guide](api-integration.md#4-store).
Treat the entity definition as part of the contract with your application and keep both
sides in step.

## 5. Changing a definition later

You can edit an entity from its **Edit** action. What an edit does to records you already
hold:

| Change | Effect |
|---|---|
| Display Name | Cosmetic only |
| Validation Regex, Max Size, MIME types | Apply to **new stores only**. Existing records are not re-checked or removed |
| Policy hold | Applies to new records only. Each record keeps the hold it was stored with |
| Active off | New stores are refused (`404`), and the entity disappears from `get_authorized_entities` and from search results. Records already stored remain in the database |
| Flavour | The console lets you edit it, but **do not change it once records exist**. Records were encrypted and indexed for the old flavour, and the vault does not convert them. Create a new entity instead |
| Entity Code | Cannot be changed. Create a new entity |

## 6. Create an API key for each application

Open **API Keys** in the console and generate a key, giving it a name such as
`Analytics-Service-Prod`. Use one key per application, and a separate key for anything
that handles erasure requests.

- The console shows the **API Key ID** and the **secret** once. The secret is stored only
  as a salted PBKDF2 hash, so it **cannot be shown again**. If it is lost, create a new key.
- Keep the secret on your server. Never ship it in a browser or mobile app.
- A key can be deactivated. A missing, inactive or wrong key or secret returns `401`.
- Creating and changing keys needs the `SYSTEM_ADMIN` role.

## 7. Grant permissions

Open **Permissions** on the key and add a grant:

1. **Type:** `ENTITY` for personal data, or `UTILITY` for a credential.
2. **Resource:** pick the entity (or utility) from the list. For a utility, the resource is
   its label.
3. Tick **READ**, **WRITE** or both, and commit.

One key has at most one grant per resource. Granting again replaces the flags. The two
flags are independent, and write does not imply read.

| Permission | Allows |
|---|---|
| **READ** on an entity | `fetch_data` and the other fetch calls, `search_data` results for that entity, and `get_erasure_certificate` |
| **WRITE** on an entity | `store_data`, and `shred_principal` when the key has write on **every** entity the person has records in |
| **READ** on a utility | `resolve_utility` |

Rules worth following:

- **Least privilege.** Give a key only the entities it needs, and only the flags it needs.
  A reporting service that only looks things up needs read and no write.
- **Keep erasure separate.** Give write on erasable entities only to the key that handles
  erasure requests. A shred needs write on all of a person's entities, otherwise it is
  refused with `403` and nothing is changed.
- **Check what a key can do.** The key calls `get_authorized_entities` and sees its own
  entities, flavours and flags. If a store returns `403`, this tells you whether it is a
  missing grant or a wrong entity code.

## 8. Checklist

- [ ] One entity per kind of value, with a code you will not need to change.
- [ ] Each flavour matches the data: `ID` for identifiers, `DATA` for text, `FILE` for documents.
- [ ] Regexes, size limits and MIME types are set, and tested with a bad value (expect `422`, `413`, `415`).
- [ ] The policy hold for each entity is agreed with compliance before records are stored.
- [ ] Each application has its own key, and its secret is stored in your server's secret store.
- [ ] Each key has only the read and write grants it needs.
- [ ] The key that erases people is separate from the keys that store.
