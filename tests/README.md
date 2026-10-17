# Tests

For contributors and CI. These tests start their own throwaway instances, and the Java
tests are Maven's test sources (`java/`). If you want scripts to run against your own
vault to try it or check its behavior, see [`../examples`](../examples/README.md).
The end-to-end runner here (`runners/run-e2e.sh`) uses those example scripts as its
test cases.

All runner scripts are in [`runners/`](runners/). Each one creates and removes its own
containers.

| File | Purpose |
|---|---|
| [`test-cases.md`](test-cases.md) | Functional test cases for key management: LOCAL and AWS KMS anchors, activation, re-wrap, fail-closed behavior. Run by hand against a throwaway instance. |
| [`load-testing-plan.md`](load-testing-plan.md) | Methodology, endpoint mapping, sizing and thresholds for load testing. Read this before a real run. |
| `java/.../CustodyServicePostgresTest` | Custody lifecycle and certificate data (grouping by record and kind, reference-key fallback, erased records, chain verification and refusal when broken). Run with `TEST_CLASS=CustodyServicePostgresTest tests/runners/run-erasure-tests.sh`. |
| `runners/run-audit-chain-tests.sh` | JUnit tests of the audit hash chain (edited, deleted and forged rows, append-only guard, concurrent writers). Same setup as the erasure runner. |
| `runners/run-erasure-tests.sh` | JUnit tests of the erasure service (shred, policy hold, legal holds, resumability, external object cleanup) against a throwaway PostgreSQL with `db/*.sql` applied. Needs docker and mvn. |
| `runners/run-e2e.sh` | Builds the war, starts it with a throwaway PostgreSQL and runs the fixtures setup and the store-fetch, search, access, validation, utilities and erasure example scripts over the HTTP APIs. Needs docker, mvn, curl and jq. |
| `vault-data-plane-test.jmx` | Apache JMeter plan for the client data plane. |
| `load-test.properties` | Concurrency, request counts and credentials for the JMeter plan. |

## Load test quick start

Runnable [Apache JMeter](https://jmeter.apache.org/) test against the client
API (`/api/client/vault`). It covers storing records, a store then fetch round
trip with value verification, blind index search, entity discovery and utility
resolution.

### Prerequisites

- Apache JMeter 5.6.3 or later (needs only a JRE; unpack the binary
  distribution).
- A running vault: **local Docker Compose or a dedicated staging instance
  only. Never production, never real personal data.**
- The key anchor health check passing (the data plane returns 503 otherwise).

### Set up test credentials

Fastest: run `examples/scripts/setup/setup-test-fixtures.sh`. It creates the
entity, key, utility and a seeded search record, and writes
`tests/load-test.local.properties` (git-ignored). Then pass that file to JMeter
with `-q` and skip the manual steps and the seed step below.

Manually, using the admin console:

1. **Entities** (`entities.html`): create or pick a throwaway entity type of
   flavor `ID` or `DATA`. Its code is `entity.code`.
2. **API Keys** (`apikeys.html`): register a test client and grant it READ and
   WRITE on that entity, and READ on one utility. Copy the key into
   `api.key` and the secret into `api.secret`. The raw secret is shown only
   once, at creation.
3. **Utility**: enroll a test utility (for example a dummy API key) and grant the
   key READ on it. `utility.id` is the utility's **label**, which is what
   `resolve_utility` matches on.

### Seed the search term

The search stage looks up a value that already exists, so a hit is a real
index match rather than an empty result. Store one record once:

```bash
curl -s http://localhost:8081/api/client/vault \
  -H "X-API-Key: $APIKEY" -H "X-API-Secret: $APISECRET" -H 'Content-Type: application/json' \
  -d '{"_func":"store_data","entityType":"ID","entityName":"<ENTITY_CODE>","content":"LOADTEST-SEED-0001"}'
```

Then set `search.term` in `load-test.properties` to a value from it, for
example `LOADTEST-SEED-0001`. The search term must be 3 to 100 characters.

### Configure

Edit `load-test.properties`. Each stage has a `<stage>.threads` and
`<stage>.loops` pair, so total requests for a stage are `threads x loops`.
Any value can be overridden on the command line with `-J`.

### Run

Non-GUI mode only for real load:

```bash
cd tests
jmeter -n -t vault-data-plane-test.jmx -q load-test.properties \
  -l results.jtl -e -o report/
```

With the fixtures script, use `-q load-test.local.properties` instead.

Override a single value:

```bash
jmeter -n -t vault-data-plane-test.jmx -q load-test.properties \
  -Jsearch.threads=50 -Jsearch.loops=200 -l results.jtl -e -o report/
```

Smoke check (one request per stage):

```bash
jmeter -n -t vault-data-plane-test.jmx -q load-test.properties \
  -Jstore.threads=1 -Jstore.loops=1 -Jround_trip.threads=1 -Jround_trip.loops=1 \
  -Jsearch.threads=1 -Jsearch.loops=1 -Jdiscovery.threads=1 -Jdiscovery.loops=1 \
  -Jutility_resolve.threads=1 -Jutility_resolve.loops=1 -l results.jtl
```

### Output

- A live summary during the run.
- `results.jtl`: every sample.
- `report/index.html`: the HTML dashboard with throughput, error rate and
  p50, p90, p95 and p99 latency per stage.

`results.jtl` and `report/` are run output and are not committed.

### Data left behind

The store and round trip stages write real encrypted rows and search index
entries, and the vault has no client delete function. Run the load test on a
disposable database (`docker compose down -v` resets it) or accept the
accumulated test rows.

## Known limitations

- No spike or soak scenario is built in. See the plan for how to extend it.
- Only client-observed latency and errors are measured. Check the server
  logs and `pg_stat_activity` for connection pool pressure.
- A stage cannot be switched off from the properties file. Disable its thread
  group in the JMeter GUI, or set its loops to 1.
