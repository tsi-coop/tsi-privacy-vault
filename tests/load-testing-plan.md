# Load Testing Plan: Vault Data Plane

**Purpose:** a repeatable, tunable way to measure throughput, error rate and
latency across the vault's client API, and to compare the cost of the LOCAL
and AWS KMS key anchors under concurrent load.

**Where to run:** local Docker Compose or a dedicated staging instance only.
Never production, and never against real personal data. Use a throwaway
entity type, client API key and utility.

---

## 1. Endpoints covered

All calls are `POST /api/client/vault` with `X-API-Key` and `X-API-Secret` headers.

| Stage | `_func` | Permission | What it exercises |
|---|---|---|---|
| 01 Store | `store_data` | WRITE | DEK generation at the anchor, local AES encryption, row insert, blind index inserts (FULL, PART, PREFIX). Expects HTTP 201. |
| 02 Round trip | `store_data`, then `fetch_data` | WRITE, READ | Store, then fetch by `reference_key`. Asserts the fetched value equals what was stored, so it catches wrong-key and corrupted-ciphertext bugs, not just status codes. |
| 03 Search | `search_data` | READ | Keyed hash, index lookup, per-row authorization check. No decryption. |
| 04 Discovery | `get_authorized_entities` | READ | Permission join. Cheap, a baseline for framework overhead. |
| 05 Utility resolve | `resolve_utility` | READ | Utility decrypt, which also involves an anchor unwrap and the machine identity check. |

**Not covered:** the admin plane (`/api/admin/*`), including `activate_key_anchor`
and `rewrap_data_keys`. Those are one-off operations covered by the functional
cases in [`test-cases.md`](test-cases.md). The `FILE` flavour is also excluded,
since payload size would dominate and `VAULT_MAX_UPLOAD_KB` caps it.

---

## 2. What makes this system different to load test

- **The anchor is on the hot path.** Every store calls `GenerateDataKey` and
  every fetch or resolve calls `Decrypt` at the active anchor. With LOCAL this
  is an in-process AES operation. With AWS KMS it is a network call that is
  subject to the account's KMS request quota and to throttling (the provider
  retries three times with backoff).
- **Run the same plan twice and compare**: once with the LOCAL anchor active,
  once with AWS_KMS active (or LocalStack for a relative, not absolute,
  comparison). The delta is the real cost of the cloud anchor.
- **Every store writes several index rows.** A multi-word value inserts a FULL
  row, one PART row per word and a PREFIX row. Database write volume per
  stored value is higher than one row.
- **The search index only grows.** The vault has no client delete, so each
  run adds rows. Use a disposable database.
- **Fail-closed gate.** If the key anchor is unhealthy the data plane returns
  503 for every stage. Confirm the health check passed before starting.

---

## 3. Tooling

**Apache JMeter** (Apache-2.0, matching this project's license).

- Concurrency and request count per stage from a `.properties` file or `-J`
  overrides, with no code edits.
- Throughput, error rate and p50, p90, p95, p99 latency from the built-in HTML
  dashboard (`-e -o report/`), and every sample in a `.jtl` file.
- Runs from an unpacked binary distribution with only a JRE.

Install from [jmeter.apache.org](https://jmeter.apache.org/download_jmeter.cgi).
The plan targets JMeter 5.6.3.

---

## 4. Test types

Run in this order. Do not start with a large number.

| Test type | Purpose | Suggested shape |
|---|---|---|
| **Smoke** | Confirm the plan, credentials and environment work | 1 thread, 1 loop per stage |
| **Load** | Sustained expected peak | Defaults in `load-test.properties` |
| **Stress** | Find the breaking point | Raise `round_trip.threads` in steps (for example 10, 25, 50, 100) until error rate or p95 crosses the threshold |
| **Soak** | Find leaks and exhaustion that appear over time | About 10 threads with a very high loop count for hours, on `round_trip` |
| **Anchor comparison** | Cost of the cloud anchor | Same load run under LOCAL, then under AWS_KMS |

### Sizing against the real constraint

`PoolDB.java` configures HikariCP with `maximumPoolSize = 10`,
`minimumIdle = 5` and a 30 second `connectionTimeout`. That pool is the ceiling
on concurrent database work, so it is the better anchor for thread counts than
a round number.

- **Load baseline:** keep write stages (`store`, `round_trip`) at 5 to 10
  threads so you measure normal behavior and not induced queuing.
- **Stress:** push `round_trip` well past the pool size. Where errors begin is
  the capacity number worth recording. A failure at roughly 30 seconds elapsed
  is a connection acquisition timeout.
- **Running all stages at once** multiplies total concurrency. The defaults
  total 30 threads against a pool of 10, so expect queuing latency. For clean
  per-stage numbers, run one stage at a time by setting the others to 1 loop.

### Traffic mix

A planning guide, not enforced by the plan. Typical vault traffic is
read-dominated.

| Stage | Suggested share |
|---|---|
| Fetch (inside round trip) | ~40% |
| Search | ~25% |
| Store | ~20% |
| Utility resolve | ~10% |
| Discovery | ~5% |

### Thresholds (starting defaults)

- **Error rate:** under 1% for a load test. Separate business errors (403 for
  a missing permission, 404 for an unknown reference) from system errors
  (5xx, timeouts) before judging. The plan asserts the HTTP status, and for
  round trip also the returned value.
- **Latency:** p95 under 500 ms and p99 under 1000 ms for `fetch_data` and
  `search_data` under the LOCAL anchor. Expect more under AWS KMS, bounded by
  the round trip to the KMS region. Record the observed numbers rather than
  treating day one as a pass or fail gate.
- **Throughput:** record the measured requests per second at target latency
  and compare against the next run.

---

## 5. Configuration

Edit [`load-test.properties`](load-test.properties).

```properties
base.url=http://localhost:8081
api.key=REPLACE_WITH_TEST_API_KEY
api.secret=REPLACE_WITH_TEST_API_SECRET
entity.code=REPLACE_WITH_ENTITY_CODE
entity.type=ID
search.term=REPLACE_WITH_SEEDED_SEARCH_TERM
utility.id=REPLACE_WITH_UTILITY_ID
ramp.up.seconds=5

store.threads=5
store.loops=40
round_trip.threads=5
round_trip.loops=40
search.threads=10
search.loops=100
discovery.threads=5
discovery.loops=40
utility_resolve.threads=5
utility_resolve.loops=40
```

Total requests per stage are `threads x loops`. The round trip stage issues two
requests per iteration.

Seed `search.term` once before the first run so the search stage hits a real
index entry (see [`README.md`](README.md)).

For a soak test, open the plan in the JMeter GUI and give the thread group a
scheduler duration, or set a very high loop count and stop the run manually.

---

## 6. Running

```bash
cd tests
jmeter -n -t vault-data-plane-test.jmx -q load-test.properties \
  -l results.jtl -e -o report/
```

Override values without editing the file:

```bash
jmeter -n -t vault-data-plane-test.jmx -q load-test.properties \
  -Jround_trip.threads=50 -Jround_trip.loops=200 -l results.jtl -e -o report/
```

Outputs are `results.jtl` (every sample) and `report/index.html` (dashboard).

---

## 7. Verifying correctness under load

Throughput numbers mean little if data is being corrupted. After a run:

1. **No anchor errors:** the application log has no `KMS` or
   `InvalidCiphertextException` lines, and `event_log` has no new `ERROR`
   rows for `KMS_HEALTH_CHECK`.
2. **Round trip assertions all passed:** the report shows 0 errors on
   `fetch_data`. An assertion failure means a fetched value did not match the
   stored one.
3. **No connection leak:** in Postgres,
   `SELECT state, count(*) FROM pg_stat_activity GROUP BY state;` shows no
   connections stuck `active` or `idle in transaction` once the run ends, and
   the idle count settles at or below the pool maximum.
4. **Version stamping:** `SELECT key_version, payload_cipher, count(*) FROM
   vault_entities GROUP BY 1, 2;` shows new rows under the active key version
   and cipher.

---

## 8. Known limitations

- No spike scenario. A burst test needs JMeter's Ultimate Thread Group or a
  Synchronizing Timer.
- Client-side metrics only. Pool pressure and JVM behavior must be read from
  server logs and `pg_stat_activity`.
- No per-stage on/off switch in the properties file.
- Admin plane and `FILE` flavour are not covered.
- This plan has not been validated against a live instance in this
  repository yet. Run a smoke test first and report any assertion that needs
  adjusting for your entity configuration.
