# Erasure Management Guide

> Before this: [Entities, API Keys and Permissions](entity-management.md) and [API Integration](api-integration.md), because erasure works on records you stored with a `principal_id`. Next: [Audit and Access Control](audit-and-access-control.md). All guides: [where to start](README.md).

How to run erasure by principal: set a policy hold, link records to a person,
handle an erasure request, and prove what was destroyed and what was kept. The design
and its limits are in
[Compliance: per-principal keys and crypto-erasure](../design/architecture.md#compliance-next-per-principal-keys-and-crypto-erasure).
This guide is the operating manual.

Erasure here is **key destruction**. Every record already has its own data key.
Shredding a principal nulls the wrapped key, the content and the search index entries
of that person's records, so whatever copies exist in backups, replicas or an object
store are unreadable ciphertext. Your ledgers and audit rows stay in place. They hold
only a `reference_key` that no longer resolves.

> **Planned change.** Your consent manager will own when erasure is due, and send
> erasure requests to the vault. See
> [Consent manager integration](../design/architecture.md#compliance-next-consent-manager-integration).
> The policy hold (section 3), shred, legal holds, register and certificate described
> here stay. A policy hold is the days your organisation must keep a record regardless of
> consent, so it is not something the consent manager knows about.

This is an engineering control, not legal advice. Whether crypto-erasure satisfies a
given statute, and which records must be retained, is for your counsel to decide.

---

## 1. Concepts

| Term | Meaning |
|---|---|
| **Principal** | The person or entity the data belongs to, identified by an opaque `principal_id` that your application supplies. Never a name, PAN or phone number |
| **Erasable record** | A record with no policy hold, or whose hold has ended. A shred destroys it |
| **Retained record** | A record still inside its policy hold. A shred leaves it readable |
| **Policy hold** | Set per entity type: the number of days from creation during which a record cannot be erased. Statutory or company policy |
| **Legal hold** | A block on a principal, with no end date, placed by an administrator. While one is open, nothing of theirs is destroyed |
| **Erasure Register** | One row per principal with an erasure request. It holds no key material |

### Principal states

| State | Meaning |
|---|---|
| `SHREDDING` | A shred is running. Reads of erasable records already fail. The job finishes the destruction |
| `PARTIAL` | Erasable records are destroyed. Some records are retained. `next_due` says when the earliest becomes erasable |
| `SHREDDED` | Nothing readable is left for this principal |

Once a principal has any register entry, **new records for it are rejected** with
`409`, in every state.

## 2. Before you start

1. **Apply the schema.** Existing databases need both scripts. Fresh installs get them
   automatically.
   ```bash
   psql -U tsi_admin -d tsi_privacy_vault -f db/02_file_storage.sql
   psql -U tsi_admin -d tsi_privacy_vault -f db/03_erasure.sql
   ```
2. **Agree the policy with your compliance team.** The vault enforces a policy hold and
   never decides it. You need, per entity type: no hold, or how many days from creation.
3. **Use the right admin.** Everything that destroys data or changes policy state through the admin API needs
   the `SYSTEM_ADMIN` role. Client keys with write access can erase a principal (section 5.5). Reading the register, certificates and holds works for any
   signed-in admin. The vault only allows one `SYSTEM_ADMIN` account to be created, so
   decide who holds those credentials and how they are protected. Two-person approval is not built.
4. **Decide the job interval.** `TSI_PRIVACY_VAULT_ERASURE_JOB_MINUTES` in `.env`
   (default 60, `0` disables). It is how late a record can be shredded after its
   policy hold ends.

## 3. Set a policy hold

Open **Entities** in the admin console (see [Entities, API Keys and Permissions](entity-management.md#3-create-an-entity)), create or edit an entity, and fill **Policy hold
in days**. Leave it empty for no hold.

| Choice | Stored as | Effect |
|---|---|---|
| No hold | `retain_days` empty | Records can be shredded immediately |
| Hold N days | `retain_days: N` | `retain_until` is creation time plus N days |

The same field works through the admin API (`create_entity` and `update_entity`).
`retain_days` is a whole number from 0 to 36500.

Rules to keep in mind:

- **The hold is copied onto each record when it is stored.** Changing it later does not
  shorten or extend what existing records were promised.
- **Records stored before the hold existed have no `retain_until`.** They are treated as
  erasable. If you are adding a hold to an entity that already holds regulated records,
  tell your counsel.
- **An entity with no hold is erasable at once.** That is the default.
- **A hold is not consent.** Whether a person's data is still needed for a purpose is the
  consent manager's call. The policy hold only says how long you must keep the record
  even if they ask. For a block with no end date, such as litigation, use a legal hold
  (section 7).

## 4. Link records to a principal

Send `principal_id` when you store:

```json
{ "_func": "store_data", "entityType": "DATA", "entityName": "KYC_DOC",
  "content": "<base64>", "principal_id": "cust-8841" }
```

- It is optional, 1 to 100 characters from `A-Z a-z 0-9 . _ : -`.
- Records stored without it work exactly as before, but cannot be erased as a group.
  They can only be shredded one at a time by `reference_key`.
- **Existing records have no principal.** Linking them means re-storing them with a
  `principal_id`, which is an application decision.
- **Use one `principal_id` per relationship** when the same person has relationships you
  may need to erase at different times, because erasure is scoped by principal.
- Keep personal identifiers out of your own ledgers and link by `reference_key`.
  Otherwise erasing the vault does not erase the identity from your system.

## 5. Handle an erasure request

> **From your application.** A client can erase a person with its own API key, see
> [section 5.5](#55-erase-from-a-client-application). The **Data Client** in the tour has an
> **Erase a person** button for trying it. Use a test principal.

### 5.1 Check before you act

1. Confirm the identity of the requester and map them to a `principal_id`. The vault
   cannot do this for you, and it cannot find a principal from personal data.
2. Check for legal holds on that principal (`list_legal_holds`). A hold refuses the
   whole request.
3. Check whether the principal is already in the register (`get_erasure_register`).
4. Tell the requester what will be retained and why, before you run it. A shred cannot
   be undone.

### 5.2 Run the shred

Log in, then call the erasure endpoint:

```bash
TOKEN=$(curl -s -X POST "$BASE_URL/api/admin/login" -H 'Content-Type: application/json' \
  -d '{"_func":"admin_login","email":"admin@example.com","password":"..."}' | jq -r .token)

curl -s -X POST "$BASE_URL/api/admin/erasure" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"_func":"shred_principal","principal_id":"cust-8841","confirm":"cust-8841"}'
```

`confirm` must repeat the `principal_id`. A mismatch returns `400` and touches nothing.

Response:

```json
{
  "success": true,
  "principal_id": "cust-8841",
  "state": "PARTIAL",
  "records_destroyed": 4,
  "records_retained": 2,
  "next_due": "2031-03-31T00:00:00Z"
}
```

What happened, in order:

1. If a legal hold is open, the request is refused with `409` and logged. No register
   entry is created and no key is touched.
2. The register entry is written as `SHREDDING`, and every erasable record is marked
   erased in one statement. From here reads of those records fail and new stores for
   the principal are rejected.
3. A batch job destroys, per record: the wrapped key (in its own commit), the content,
   the value hash, the file name, the blind index entries, and finally any object in S3.
4. The state moves to `SHREDDED` if nothing is retained, otherwise `PARTIAL`.

The call is idempotent. Run it again on a `SHREDDING` or `PARTIAL` principal and it
re-evaluates the policy hold and finishes whatever is left.

### 5.3 Check the result

```bash
curl -s -X POST "$BASE_URL/api/admin/erasure" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"_func":"get_erasure_certificate","principal_id":"cust-8841"}'
```

```json
{
  "success": true,
  "principal_id": "cust-8841",
  "state": "PARTIAL",
  "requested_by": "admin@example.com",
  "requested_at": "2026-10-13 16:02:11.4",
  "shredded_at": null,
  "destroyed": [
    { "reference_key": "...", "entity_code": "MARKETING_PREF", "flavor": "DATA",
      "erased_at": "2026-10-13T10:32:11Z", "key_destroyed": true }
  ],
  "retained": [
    { "reference_key": "...", "entity_code": "KYC_DOC", "flavor": "FILE",
      "retain_until": "2031-03-31T00:00:00Z" }
  ],
  "machine_id": "NODE:MUMBAI_DC_RACK04_SRV01",
  "generated_at": "2026-10-13T16:05:00"
}
```

- `key_destroyed: false` on a destroyed record means the object delete is still being
  retried. The key is already gone, so the object is unreadable.
- The certificate lists reference keys and entity codes only, never values.
- It shows a regulator why each retained record was kept.

### 5.4 Tell the requester

State what was destroyed, what is retained, the basis, and the date it will be
destroyed (`next_due`).

### 5.5 Erase from a client application

The same erasure can be requested on the client API, with the API key and secret your
application already uses to store and fetch.

```json
{ "_func": "shred_principal", "principal_id": "cust-8841", "confirm": "cust-8841" }
```

```json
{ "_func": "get_erasure_certificate", "principal_id": "cust-8841" }
```

- **Authorization.** The key needs **write** access to every entity type that holds a record
  of the person, or the request returns `403` and nothing is touched. The certificate needs
  **read** access to the same types. A key can therefore never erase data it may not change.
  Grant write on erasure-capable entities only to the key that handles erasure requests.
- **What is enforced is the same.** An open legal hold returns `409`, records inside their
  policy hold stay readable, and the response and the states are those of section 5.2.
- **Unknown principal.** A `principal_id` with no records returns `404`, so a typo cannot
  put a register entry in front of a person who has no data yet.
- **Audit.** The request is logged as `ERASURE_SHRED:<principal>` by `VAULT:<api key id>`,
  and a refusal for missing write access is logged as `DENIED`.
- **In the console.** The register shows it with a **Client API** badge and the key id.
  Single-record shredding, legal holds and the manual job stay admin only.

## 6. Legal holds

A legal hold overrides a policy hold and blocks every destruction path for that principal: a
manual shred, a single-record shred, and the scheduled job.

```json
{ "_func": "place_legal_hold", "principal_id": "cust-8841",
  "reason": "Regulatory inquiry", "case_ref": "CASE-2026-114" }
```

```json
{ "_func": "list_legal_holds", "open_only": true }
{ "_func": "release_legal_hold", "hold_id": 7 }
```

- `reason` and `case_ref` are stored in the clear. **Do not put personal data in them.**
- A hold placed while a principal is `PARTIAL` stops the scheduled shred until it is
  released. The next job pass after release picks it up.
- A hold does not undo anything already destroyed.

## 7. Single records

To destroy one record by `reference_key`, for a record with no principal or for a
single item:

```json
{ "_func": "shred_record", "reference_key": "550e8400-e29b-41d4-a716-446655440000",
  "confirm": "550e8400-e29b-41d4-a716-446655440000" }
```

It honours policy holds and legal holds. A retained record returns `409` with its reason
(`retained until <time>`). Shredding an already erased record
returns `200` with `already_erased: true`.

## 8. The scheduled job

The job runs 30 seconds after boot and then every
`TSI_PRIVACY_VAULT_ERASURE_JOB_MINUTES` minutes. Each pass:

1. Finishes any destruction a crash left half done.
2. Finalizes principals still `SHREDDING`.
3. Shreds `PARTIAL` principals whose `next_due` has passed, unless a hold is open.

Every step is idempotent, so a restart or overlapping passes on several nodes are safe.

Run a pass on demand, for example after releasing a hold or after an object store
outage:

```json
{ "_func": "run_erasure_job" }
```

```json
{ "success": true, "records_drained": 12, "principals_resumed": 1,
  "principals_shredded": 2, "principals_held": 1 }
```

## 9. Reports and audit

**Console.** The **Erasure** page in the admin console (`/erasure.html`) shows all of
this without calling the API. It is read-only and open to any signed-in admin, and it
refreshes every 15 seconds. It shows:

| Section | Shows |
|---|---|
| Tiles | Principals by state (shredding, partial, shredded) and how many are on legal hold |
| Erasure register | Every principal with a request, the state, records destroyed and retained, when the next retained record is due, who asked and when. Filter by state or search by principal |
| Certificate | Opened from a register row: records destroyed and retained, with reference keys, entity codes and retain-until dates |
| Legal holds | Open holds, or all of them, with reason, case reference and who placed or released them |
| Erasure job | Status (`HEALTHY`, `FAILING`, `OVERDUE`, `WAITING`, `DISABLED`), last run, last success and next expected run. **View job history** opens `/erasure-jobs.html`, with 30 day totals and every pass, and a link back |
| Recent erasure activity | The latest `ERASURE_*`, `LEGAL_HOLD_*` and refused (`ADMIN_ERASURE:*`) events from the audit log, filterable by outcome |

Requests appear as soon as they reach the vault, whether they came from your own
application, the example scripts or a manual call. A principal in `SHREDDING` for more
than a few minutes means the batch job could not finish. Check the backend and the
activity list for an `ERROR`, then run the job again (`run_erasure_job`).

**Job history.** `get_erasure_job` returns the same data as JSON: `status`, `config`
(interval, next expected), `last_run`, `last_success`, `consecutive_failures`,
`totals_30d` and `runs`. Status is `FAILING` when the latest pass failed and `OVERDUE`
when there has been no success within twice the interval. Runs are kept 90 days. A
shred request finishes in the request itself, so a failing job delays only retention
shreds and the finishing of interrupted ones.

**Register.** `get_erasure_register`, optionally with `"state": "PARTIAL"`:

| Field | Meaning |
|---|---|
| `state` | `SHREDDING`, `PARTIAL` or `SHREDDED` |
| `records_destroyed`, `records_retained` | Counts at the last evaluation |
| `next_due` | Earliest `retain_until` among retained records |
| `on_hold` | An open legal hold exists |
| `requested_by`, `requested_at`, `shredded_at` | Who and when |

**Audit.** Every step is written to `event_log` with the actor, the machine anchor and
the outcome, and appears on the Audit page:

| Operation | Written when |
|---|---|
| `ERASURE_SHRED:<principal>:condemned=<n>` | A shred marked its erasable records |
| `ERASURE_RESULT:<principal>:<state>:destroyed=<n>:retained=<n>` | The register entry was finalized |
| `ERASURE_SHRED_RECORD:<reference_key>` | A single record was shredded |
| `LEGAL_HOLD_PLACE:...`, `LEGAL_HOLD_RELEASE:...` | A hold changed |

Refusals (an open hold, a policy hold, a non-`SYSTEM_ADMIN` caller) are logged with outcome
`DENIED` and the reason.

Erasure events sit in the same hash-chained, append-only log as everything else. Before
you issue a certificate as evidence, run `verify_audit_chain` and keep the head it
returns. See the [Audit and access control guide](audit-and-access-control.md).

## 10. What client applications see

| Call | Result for an erased principal or record |
|---|---|
| `fetch_data` and the other fetch functions | `410 Record erased`. A distinct outcome, so callers can tell erasure from corruption |
| `search_data` | The record no longer matches. Its blind index entries are gone |
| `store_data` with that `principal_id` | `409`. The principal has been erased |
| `generate_entity_bsa_certificate` | Refused. The value hash is destroyed. Use the erasure certificate |

Retained records stay fully readable, searchable and fetchable until their policy
hold ends.

## 11. Limits you must plan for

- **Backups.** A database backup or replica taken before a shred still holds the wrapped
  keys, and the key anchor can still unwrap them. Bound your backup retention and write
  it down. The Erasure Register shares the database, so a restore rolls it back with the
  data. Keep a copy of the register outside the database, and re-run `shred_principal`
  for each entry after any restore, before serving traffic.
- **Object stores.** The key is destroyed first, so the object is unreadable at once. With
  bucket versioning on, the delete only adds a marker. Add a lifecycle rule for
  noncurrent versions so the bytes do not sit there. See the
  [AWS S3 Configuration Guide](aws-s3-configuration.md#9-backup-recovery-and-erasure).
- **Irreversible.** There is no recovery path.
- **The anchor key is never the target.** Destroying it would erase every principal at
  once.
- **Your own copies.** Erasure covers the vault. Exports, logs, caches and ledgers in your
  application are yours to clear.
- **Destroyed with the key.** The row keeps its `reference_key`, entity code, flavour and
  timestamps. The value hash and file name go too, because an unsalted hash of a short
  identifier would let someone test a guess.
- **The console is read-only.** The policy hold is on the Entities page. The Erasure page
  shows the register, certificates and holds. Shred and holds are API-only for now.
- **No two-person approval.** Control access to the `SYSTEM_ADMIN` credentials.

## 12. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `400 confirm must equal principal_id` | `confirm` is missing or different. Repeat the `principal_id` exactly |
| `403 SYSTEM_ADMIN role required` | You are signed in as another role. Only `SYSTEM_ADMIN` can destroy data or change policy state |
| `409 ... an open legal hold exists` | Release the hold, or leave it. Nothing was touched |
| `409 ... record is under retention` | A single-record shred hit a retained record. Wait for `retain_until`, or ask your compliance team about the hold |
| `409 Principal has been erased` on store | The principal has a register entry. Use a new `principal_id` if this is a new relationship |
| `404 Reference not found` | Wrong `reference_key` |
| Principal stuck in `SHREDDING` | Object store delete failing, or the app stopped mid run. Fix the store, then `run_erasure_job` |
| `PARTIAL` principal never shreds | `next_due` is in the future, a hold is open, or the job is disabled (`..._ERASURE_JOB_MINUTES=0`) |
| Everything is erasable but you wanted a hold | The entity had no hold when the records were stored. Records are not re-evaluated against a later value |
| Entities page fails to load, or the dashboard File Storage card says counts are unavailable | `db/02_file_storage.sql` or `db/03_erasure.sql` has not been applied |

## 13. Testing

- `tests/runners/run-erasure-tests.sh` runs the service tests (shred, policy hold,
  legal holds, resumability, object cleanup) against a throwaway PostgreSQL.
- `tests/runners/run-e2e.sh` builds the war, boots it and runs the example scripts,
  including `examples/scripts/erasure/test-erasure.sh`, over the HTTP APIs.

See [tests/README.md](../../tests/README.md). Run the erasure example against a staging
instance before you rely on it in production. Use synthetic data only.
