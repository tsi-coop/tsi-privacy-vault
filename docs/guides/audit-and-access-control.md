# Audit and Access Control Guide

How admin roles limit what a console user can change, and how to prove the audit log
has not been altered. The design is described in
[Forensic evidence](../design/architecture.md#6-forensic-evidence) and
[Admin roles](../design/architecture.md#admin-roles).

---

## 1. Admin roles

| Role | Can do |
|---|---|
| `SYSTEM_ADMIN` | Everything: read, and every function that changes state |
| Any other role (`AUDITOR`, or `AUDIT_VIEWER`, the default for new users) | Read only: entities, API keys, permissions, key anchor status, audit logs, the legal ledger, certificates, the dashboard and the erasure register |

Only the exact role `SYSTEM_ADMIN` can write. Every other role name is read only, and a
token with no role at all is refused on write functions.

### What needs `SYSTEM_ADMIN`

| Endpoint | Functions |
|---|---|
| `/api/admin/user` | All of them: `list_users`, `create_user`, `generate_master_recovery_key` |
| `/api/admin/keyanchor` | `activate_key_anchor`, `rewrap_data_keys` |
| `/api/admin/entity` | `create_entity`, `update_entity` |
| `/api/admin/apikey` | `create_key`, `update_key` |
| `/api/admin/permission` | `create_permission`, `delete_permission` |
| `/api/admin/utility` | `enroll`, `checkout`, `rotate`. `checkout` returns a secret in the clear, so it is treated as a write |
| `/api/admin/erasure` | `shred_principal`, `shred_record`, `place_legal_hold`, `release_legal_hold`, `run_erasure_job` |

Not covered by roles: `setup` and `resetpass`. They are reachable without a login and are
protected by the bootstrap token and the master recovery key.

### What a refusal looks like

The call returns `403`:

```json
{ "status": 403, "error": "SYSTEM_ADMIN role required.", "timestamp": "..." }
```

and an `event_log` row is written with the actor, outcome `DENIED`, reason `role` and an
operation of the form `ADMIN_<AREA>:<FUNCTION>`, for example
`ADMIN_ENTITY:CREATE_ENTITY`. Review these on the Audit page. Repeated denials from one
account usually mean a user needs a different role, or an account is misused.

### Upgrading

Accounts that relied on the old behaviour lose write access without notice. Before
upgrading, list your users and make sure whoever manages entities, keys, anchors and
secrets has the `SYSTEM_ADMIN` role. Only one `SYSTEM_ADMIN` can be created through
setup, so plan who holds it.

---

## 2. Tamper-evident audit log

Every `event_log` row stores `prev_hash` and `row_hash`. The hash covers the row's own
fields and the hash of the row before it. Changing, removing or re-ordering any row
breaks the chain from that row onward, and the verify call points at the first break.

The table is also append-only: `UPDATE`, `DELETE` and `TRUNCATE` are rejected by the
database with `event_log is append-only`.

### 2.1 Apply the schema

Fresh installs get it automatically. On an existing database:

```bash
psql -U tsi_admin -d tsi_privacy_vault -f db/04_audit_chain.sql
```

Rows already in the log are chained in `log_id` order at that moment. History before the
migration is protected from then on, not retroactively. The script is safe to run twice.

Until it is applied, `verify_audit_chain` returns an error.

### 2.2 Verify the chain

Any signed-in admin, including `AUDITOR`, can run it:

```bash
curl -s -X POST "$BASE_URL/api/admin/audit" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"_func":"verify_audit_chain"}'
```

Intact:

```json
{ "valid": true, "rows_checked": 18422, "head_seq": 18422, "head_hash": "9f2c...e1" }
```

Broken:

```json
{ "valid": false, "rows_checked": 7013, "first_bad_seq": 7014,
  "reason": "row content does not match its hash" }
```

| `reason` | Meaning |
|---|---|
| `row content does not match its hash` | A field of that row was edited |
| `prev_hash does not match the previous row` | The row was moved, or a neighbour was replaced |
| `row missing from the chain` | A row was deleted. `first_bad_seq` is the missing position |
| `rows exist outside the chain ...` | Rows were inserted with the trigger bypassed |
| `recorded head row is missing`, `recorded head hash does not match` | The tail was truncated or rewritten (see 2.3) |

`rows_checked` counts rows verified before the problem. To check only recent history, pass
`"from_seq": 7000`. It trusts the stored hash of the row before the start point.

Verification reads the whole log, so on a very large table run it off-peak.

### 2.3 Record the head outside the database

A hash chain alone cannot detect the removal of the newest rows, or a complete rewrite by
someone with database owner rights. The defence is a copy of the head held somewhere the
database owner cannot edit.

1. After each verify, store `head_seq` and `head_hash` in a system the database
   administrators do not control: a signed report, a ticket, a WORM bucket or a separate
   log.
2. On the next verify, pass them back:

   ```bash
   curl -s -X POST "$BASE_URL/api/admin/audit" \
     -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"_func":"verify_audit_chain","expected_head_seq":18422,"expected_head_hash":"9f2c...e1"}'
   ```

   The chain must still contain that row with that hash. Both fields must be supplied
   together.

Every BSA Section 63 certificate also records the head at the moment it was issued
(see 2.4), so certificates you have handed out are themselves recorded heads.

Do this on a schedule that matches your evidence needs. Monthly is a sensible start for
most deployments, and before any regulator or court submission.

### 2.4 What the BSA certificate shows

`generate_entity_bsa_certificate` (`/api/admin/legal`) adds an **Audit log integrity**
block to the PDF:

| Line | Meaning |
|---|---|
| Event: sequence, Event hash | The `STORE` event the certificate is about |
| Log head at issue: sequence, Head hash | The newest row when the certificate was issued |
| Chain verified ... at | When the chain from that event to the head was checked, in UTC |

Before issuing, the vault verifies the chain from the event to the head. If it fails the
call returns `409` ("Audit chain verification failed at sequence N ... certificate not
issued") and no PDF is produced. If the event is not in the chain at all, apply
`db/04_audit_chain.sql`. `Software Source` shows the running version from `pom.xml`.

Keep the PDF. To check it later, run `verify_audit_chain` with the certificate's head as
`expected_head_seq` and `expected_head_hash` (2.3).

### 2.5 Limits

- **Detection, not prevention.** The database owner can disable the triggers and rewrite
  the table. They cannot do it without `verify_audit_chain` failing, unless they also
  rewrite every later row and you have no earlier head on record. Run the vault as a
  database role that does not own `event_log`, and keep recorded heads.
- **One writer at a time.** New rows queue on a database lock so the chain cannot fork.
  Each audit write commits immediately, so the cost is small, but audit writes are
  serialized.
- **Timestamps** are hashed in UTC, so changing a session or server time zone does not
  break the chain.
- **Event content is only as good as its source.** The chain proves the log was not
  changed after it was written. It does not prove that an event was logged in the first
  place.

---

## 3. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `403 SYSTEM_ADMIN role required.` | The account is not `SYSTEM_ADMIN`. Use the right account rather than loosening the role |
| `function verify_event_log_chain does not exist` | `db/04_audit_chain.sql` has not been applied |
| `event_log is append-only` from your own tooling | A retention or clean-up script updates or deletes audit rows. It must stop. Export and archive instead |
| `valid: false` right after a restore | The restore did not preserve `chain_seq`, `prev_hash` or `row_hash`, or restored rows out of order. Restore the table in full from one backup |
| `valid: false` with `rows exist outside the chain` | A load or migration inserted rows with the trigger disabled. Treat as an incident until explained |
| Test setup needs to empty `event_log` | Only on a throwaway database: `ALTER TABLE event_log DISABLE TRIGGER USER;` then truncate, then `ENABLE TRIGGER USER` |

---

## 4. Testing

```bash
tests/runners/run-audit-chain-tests.sh
```

Starts a throwaway PostgreSQL container, applies `db/*.sql`, and runs
`AuditChainPostgresTest`: edited, deleted, forged and bypassed rows are detected, UPDATE,
DELETE and TRUNCATE are rejected, and 8 concurrent writers produce one unbroken chain.
Role logic is covered by `RoleGuardTest`, which needs no database. To
exercise a denial end to end, call a write function with an `AUDITOR` login and check for
the `403` and the `DENIED` row.
