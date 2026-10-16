# API Integration Guide: Store, Fetch and Search

How an application talks to the vault's data plane. It covers the three calls you
build a product on (`store_data`, `fetch_data`, `search_data`), the rules the vault
enforces on them, and the errors you must handle. Request and response shapes here
match what the server does today.

Related guides:
[Erasure Management](erasure-management.md) for `principal_id`, the policy hold and erasure,
[AWS S3 Configuration](aws-s3-configuration.md) for where files are kept, and the
[API tour](../../web/tour/api.html) for an interactive view.

---

## 1. The model in one minute

- You send plaintext over TLS. The vault encrypts it with a fresh data key and keeps
  only ciphertext. You get back an opaque **`reference_key`** (a UUID).
- Store that `reference_key` in your own database, instead of the personal data. Fetch
  the value later with it.
- To find records without knowing their reference key, use **search**. It matches a
  blind index of the value, so the vault never decrypts to search.
- What a key may do is controlled per **entity** (an entity is a named type of value,
  such as `PAN` or `KYC_SCAN`), with separate read and write permission.

## 2. Connection and authentication

| | |
|---|---|
| Endpoint | `POST /api/client/vault` |
| Content type | `application/json` |
| Headers | `X-API-Key` and `X-API-Secret`, both required |
| Selector | `_func` in the JSON body names the operation |

```bash
curl -s -X POST "$BASE_URL/api/client/vault" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" -H "X-API-Secret: $API_SECRET" \
  -d '{"_func":"get_authorized_entities"}'
```

- Create keys and grant per-entity read and write on the **API Keys** page of the admin
  console. The secret is shown once.
- Send the secret from a server, never from a browser or mobile app. The tour pages
  put it in a browser only because they are a demo.
- Only `POST` is accepted. Any other method returns `405`.
- A missing, inactive or wrong key or secret returns a plain **`401 Unauthorized`**, not
  a JSON body. Handle it by status code.

### Discover what a key can do

```json
{ "_func": "get_authorized_entities" }
```

```json
{ "success": true,
  "entities": [
    { "entity_code": "PAN", "flavor": "ID", "can_read": true, "can_write": true },
    { "entity_code": "KYC_SCAN", "flavor": "FILE", "can_read": true, "can_write": false }
  ] }
```

Use `entity_code` as `entityName` in the calls below, and `flavor` as `entityType`.
Only active entities are listed.

## 3. Entities and flavours

An administrator defines each entity once (Entities page). The definition is the
source of truth, and the vault enforces it on every store.

| Flavour | For | Content |
|---|---|---|
| `ID` | Identifiers such as PAN, Aadhaar, Voter ID | Short text, optional validation regex |
| `DATA` | Personal data such as a name, an address or a record | Text, optional validation regex |
| `FILE` | Documents and images | Binary, with allowed MIME types and a size limit |

If the `entityType` you send does not match the entity's flavour, the store is
rejected. Treat the entity definition as part of your contract and keep both sides
in step.

## 4. Store

```json
{
  "_func": "store_data",
  "entityType": "ID",
  "entityName": "PAN",
  "content": "QUJDREUxMjM0Rg==",
  "principal_id": "cust-8841"
}
```

| Field | Required | Notes |
|---|---|---|
| `_func` | yes | `store_data` |
| `entityType` | yes | `ID`, `DATA` or `FILE`. Case-insensitive. Must match the entity's flavour |
| `entityName` | yes | The entity code, up to 50 characters |
| `content` | yes | **Base64** of the value (see below) |
| `fileName` | `FILE` only | Required for `FILE`. Stored sanitized, and returned on fetch |
| `principal_id` | no | Opaque ID of the person the record belongs to. See the [Erasure Management guide](erasure-management.md) |

Response, `201 Created`:

```json
{ "success": true, "reference_key": "550e8400-e29b-41d4-a716-446655440000" }
```

### Content encoding

- **Always send Base64.** For `FILE` it is mandatory. For `ID` and `DATA` plain text is
  tolerated, but a plain value can also be valid Base64, for example `345235503650`,
  and the vault then has to guess which you meant. Encoding every value removes the
  guess.
- The vault stores and returns the **exact `content` string you sent**. Fetch gives back
  the same Base64, which you decode.
- The value is validated and indexed **after** decoding.

### What the vault checks, in order

| Status | Meaning |
|---|---|
| `400` | A required field is missing or malformed, `entityType` does not match the entity's flavour, `fileName` is missing for `FILE`, `content` is not Base64 for `FILE`, or `principal_id` has characters outside `A-Z a-z 0-9 . _ : -` |
| `403` | The key has no write permission on the entity. This is checked first, so a code the key was never granted, including a misspelt or unknown one, also returns `403` |
| `404` | The key has permission on the entity, but it is inactive |
| `409` | The `principal_id` has been erased |
| `413` | Larger than the limit. The limit is the lower of the entity's `max_size_kb` and `TSI_PRIVACY_VAULT_MAX_UPLOAD_KB` (default 5120 KB). It applies to the decoded size |
| `415` | `FILE` type problem. The type is identified from the file's content, not its name or your declared type. PDF, PNG, JPEG, GIF, ZIP-based Office files and UTF-8 text are recognised. The content must match an allowed type, and the extension must match the content |
| `422` | `ID` or `DATA` value does not fully match the entity's validation regex |
| `503` | The key anchor or the file store is unavailable, or the file backend refused the upload. Retry with backoff |

Every rejection is also written to the audit log with outcome `DENIED`.

### FILE example

```bash
B64=$(base64 -w0 contract.pdf)
curl -s -X POST "$BASE_URL/api/client/vault" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" -H "X-API-Secret: $API_SECRET" \
  -d "{\"_func\":\"store_data\",\"entityType\":\"FILE\",\"entityName\":\"KYC_SCAN\",
       \"content\":\"$B64\",\"fileName\":\"contract.pdf\",\"principal_id\":\"cust-8841\"}"
```

For large files, build the body from a file rather than a shell variable:
`curl --data-binary @request.json`.

### Things to design for

- **Store is not idempotent.** Every call creates a new record and a new
  `reference_key`. If a request times out, you cannot tell whether it landed. Decide
  how to handle a possible duplicate, for example by recording an attempt id in your
  own database before you call.
- **Size.** Base64 adds about a third. A 5 MB file is a body of roughly 6.7 MB. Check
  any proxy or gateway body limit in front of the vault.
- **Save the `reference_key` transactionally** with the business record that depends on
  it.

## 5. Fetch

```json
{ "_func": "fetch_data", "reference-key": "550e8400-e29b-41d4-a716-446655440000" }
```

Note the **hyphen** in `reference-key`, unlike the underscore in the store response. The
value must be a UUID. The schema rejects other fields.

The aliases `fetch_id_by_reference`, `fetch_data_by_reference` and
`fetch_file_by_reference` behave identically. Use `fetch_data`.

Response, `200 OK`:

```json
{
  "success": true,
  "value": "QUJDREUxMjM0Rg==",
  "flavor": "ID",
  "fileName": null
}
```

- `value` is the Base64 string you stored. Decode it.
- `flavor` is the entity's flavour, as `ID`, `DATA` or `FILE`.
- `fileName` is the sanitized name for `FILE`, otherwise `null`. For files the response also
  carries a `Content-Disposition: attachment` header.

### Errors

| Status | Meaning |
|---|---|
| `400` | `reference-key` is missing or not a UUID, or the body has unknown fields |
| `403` | The key has no read permission on the entity |
| `404` | No record with this reference |
| `410` | The record has been erased. Its keys were destroyed, so it cannot come back. Remove the reference from your side |
| `500` | A file in the object store is missing or failed its integrity check. Log it and alert. Do not retry blindly |
| `503` | The key anchor or the file backend is unavailable. Retry with backoff |

`403` and `404` are distinct, so an unauthorized caller can learn that a reference
exists. Treat reference keys as identifiers you do not publish.

## 6. Search

```json
{ "_func": "search_data", "searchTerm": "Satish" }
```

Response:

```json
{
  "success": true,
  "results": [
    { "reference_key": "550e8400-e29b-41d4-a716-446655440000", "flavor": "DATA" }
  ]
}
```

Search returns **references, not values**. Fetch each one you need.

### What can be found

The vault indexes a value when it is stored, as hashes. A search hashes your term the
same way and looks for equal hashes.

| Stored as | Indexed under |
|---|---|
| `ID` or `DATA` | The full value |
| `ID` or `DATA` with several words | Each word, in addition to the full value |
| `ID` or `DATA` | The first 3 characters of the value |
| `FILE` | The full file name, the extension (without the dot), and the name without its extension |

So these find a record stored as `Satish Kumar`:

| Term | Matches |
|---|---|
| `Satish Kumar` | Yes, full value |
| `satish` | Yes, a word. Case does not matter |
| `Kumar` | Yes, a word |
| `Sat` | Yes, the 3 character prefix |
| `Sati` | **No.** A prefix only matches at exactly 3 characters |
| `tish` | **No.** There is no substring or fuzzy search |

Rules:

- `searchTerm` must be 3 to 100 characters.
- Matching ignores case and leading or trailing spaces. Spaces **inside** a term must
  match the stored value exactly.
- Results are limited to entities the calling key can **read**, and to active entities.
  Erased records never match.
- There is no ranking and no paging. The schema accepts a `limit` field, but the
  server does not apply it today. Plan for a result set of any size, and keep terms
  specific.
- A word of 3 or fewer characters still matches as a word, but common words return many
  records.

### Choose what to search on

Search finds anything that is identical to something you stored. For a low-entropy
value, such as a 10 digit mobile number, search is effectively a lookup of
"does this exist". That is the intended use: look up by an identifier, then fetch.
Decide per entity whether it should be searchable at all.

### The index secret

Hashes are salted with `TSI_PRIVACY_VAULT_INDEX_SECRET`. **Do not change it** once
records exist, or every existing record stops matching until it is re-stored. Back it up
with the rest of the vault's secrets.

## 7. Error format

Errors from the vault return JSON with the HTTP status:

```json
{ "status": 410, "error": "Record erased.", "timestamp": "2026-10-13T10:32:11Z" }
```

Two caveats: the `401` for bad credentials is a plain status with no JSON body, and a
request that fails schema validation returns `400` with the validator's message in
`error`.

| Status | Retry? |
|---|---|
| `400`, `403`, `404`, `409`, `410`, `413`, `415`, `422` | No. The request or its state must change |
| `401` | No. Fix the key or secret |
| `500` | No, until you have looked at it |
| `503` | Yes, with exponential backoff and a cap. The vault fails closed by design when its key anchor or file store is down |

## 8. A minimal client

Python, using only the standard library plus `requests`:

```python
import base64, requests

class Vault:
    def __init__(self, base_url, key, secret, timeout=30):
        self.url = base_url.rstrip("/") + "/api/client/vault"
        self.headers = {"X-API-Key": key, "X-API-Secret": secret}
        self.timeout = timeout

    def _call(self, payload):
        r = requests.post(self.url, json=payload, headers=self.headers, timeout=self.timeout)
        if r.status_code == 401:
            raise PermissionError("bad API key or secret")
        body = r.json() if r.content else {}
        if r.status_code >= 400:
            raise RuntimeError(f"{r.status_code}: {body.get('error')}")
        return body

    def store(self, entity, entity_type, data: bytes, file_name=None, principal_id=None):
        payload = {"_func": "store_data", "entityType": entity_type, "entityName": entity,
                   "content": base64.b64encode(data).decode()}
        if file_name:
            payload["fileName"] = file_name
        if principal_id:
            payload["principal_id"] = principal_id
        return self._call(payload)["reference_key"]

    def fetch(self, reference_key) -> bytes:
        body = self._call({"_func": "fetch_data", "reference-key": reference_key})
        return base64.b64decode(body["value"])

    def search(self, term):
        return self._call({"_func": "search_data", "searchTerm": term})["results"]


vault = Vault("https://vault.internal", "<key>", "<secret>")
ref = vault.store("PAN", "ID", b"ABCDE1234F", principal_id="cust-8841")
assert vault.fetch(ref) == b"ABCDE1234F"
print(vault.search("ABCDE1234F"))
```

The same three calls from the shell are in
[`examples/scripts/store-fetch/test-store-fetch.sh`](../../examples/scripts/store-fetch/test-store-fetch.sh)
and [`examples/scripts/search/test-blind-index-search.sh`](../../examples/scripts/search/test-blind-index-search.sh).

## 9. Integration checklist

- [ ] Secrets stay on the server. Calls come from your backend, over TLS.
- [ ] You store `reference_key` and not the personal value, and your ledgers and logs
      hold no identifiers.
- [ ] Every `ID` and `DATA` value is Base64 encoded, so there is no guessing.
- [ ] Each record sent for a person carries the same opaque `principal_id`, if you need
      to erase them later.
- [ ] `410` removes the reference on your side. `503` retries with backoff.
- [ ] Your retry logic cannot create duplicates silently on a timed-out store.
- [ ] You tested size limits, a rejected file type and a regex failure for each entity.
- [ ] You treat a `403` on store as either a missing grant or a wrong entity code.
- [ ] The index secret and the vault's other secrets are backed up.

## 10. Related operations

These share the endpoint but are covered in their own guides:

| Operation | Where |
|---|---|
| `get_authorized_utilities`, `resolve_utility` | [Utility Client tour](../../web/tour/util-client.html) |
| `shred_principal`, `get_erasure_certificate` | [Erasure Management](erasure-management.md#55-erase-from-a-client-application) |
| Single-record shred, legal holds, register (admin API) | [Erasure Management](erasure-management.md) |
