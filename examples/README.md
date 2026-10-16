# Examples

For the request and response reference these scripts exercise, see the
[API integration guide](../docs/guides/api-integration.md).

Runnable scripts for trying the vault and checking its behavior against a live
instance. They use `curl` and `jq` only. They run against *your* instance. To run them
against a throwaway one that is built and removed for you, use
[`tests/runners/run-e2e.sh`](../tests/README.md).

**Use a local or staging instance only. Never production, never real personal
data.** The scripts create entities, API keys and records.

## Prerequisites

- A running vault. The default is `http://localhost:8081`. Set `BASE_URL` to change it.
- `curl`, `jq` and `base64`.
- An admin account, so the setup script can create fixtures.
- The key anchor health check passing. The data plane returns 503 otherwise.

## Scripts

| Script | What it checks |
|---|---|
| [`scripts/setup/setup-test-fixtures.sh`](scripts/setup/setup-test-fixtures.sh) | Creates an ID, DATA and FILE entity, a KEYS and a CERT utility, a read-write key and a read-only key, seeds one searchable ID record, writes the credentials to `scripts/setup/.fixtures.env`, and writes `tests/load-test.local.properties` for the [JMeter plan](../tests/README.md). |
| [`scripts/store-fetch/test-store-fetch.sh`](scripts/store-fetch/test-store-fetch.sh) | Stores one ID, DATA and FILE record, fetches each back, and compares the value. Also stores a record with a `principal_id` and checks that an invalid one is rejected. |
| [`scripts/search/test-blind-index-search.sh`](scripts/search/test-blind-index-search.sh) | Finds a stored record by full value, one word and a 3 character prefix. Checks that case and spacing do not matter. |
| [`scripts/validation/test-entity-validation.sh`](scripts/validation/test-entity-validation.sh) | Regex mismatch, flavor mismatch, MIME type and extension checks, missing file name, size limit, and invalid entity definitions. |
| [`scripts/utilities/test-utilities.sh`](scripts/utilities/test-utilities.sh) | Discovers and resolves utilities (KEYS and CERT) as a client, checks grants and unknown labels, lists them through the admin API, and rotates one. |
| [`scripts/access/test-access-control.sh`](scripts/access/test-access-control.sh) | Wrong secret, read-only key, key with no grant, unknown entity. |
| [`scripts/erasure/test-erasure.sh`](scripts/erasure/test-erasure.sh) | Erasure by principal: store with `principal_id`, shred with a policy-held record, legal hold, the scheduled job, HTTP 410 on erased records, the register and the certificate. Creates its own entities and keys, and needs a `SYSTEM_ADMIN` login. |

Each test script prints `PASS` or `FAIL` per check, a summary line, and exits
non-zero when any check fails.

## Quick start

```bash
cd examples/scripts

# 1. Create fixtures (once)
ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD='<password>' ./setup/setup-test-fixtures.sh

# 2. Run the tests. They read credentials from setup/.fixtures.env.
./store-fetch/test-store-fetch.sh
./search/test-blind-index-search.sh
./validation/test-entity-validation.sh
./access/test-access-control.sh
./utilities/test-utilities.sh
```

The erasure script does not use the fixtures. It logs in as an admin with the `SYSTEM_ADMIN` role and creates its own entities and keys:

```bash
ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD='<password>' \
VIEWER_EMAIL=viewer@example.com VIEWER_PASSWORD='<password>' \
  ./erasure/test-erasure.sh
```

`VIEWER_*` is optional. It is a second admin with any other role, used to check that only `SYSTEM_ADMIN` can destroy data. Run `db/02_file_storage.sql` and `db/03_erasure.sql` on an existing database first.

The validation script also checks entity definitions through the admin API. It
uses the admin token the setup script saved. The token expires. If those checks fail with HTTP 401, run setup again.

## Environment variables

| Variable | Used by | Default |
|---|---|---|
| `BASE_URL` | all | `http://localhost:8081` |
| `ADMIN_EMAIL` | setup | required |
| `ADMIN_PASSWORD` | setup | prompted when unset |
| `FORCE` | setup | `0`. Set to `1` to create new keys even when saved ones work. |
| `LOAD_PROPS_FILE` | setup | `tests/load-test.local.properties` |
| `PREFIX` | setup | `EX` (entity codes become `EX_ID_NUMBER`, `EX_NOTE`, `EX_DOCUMENT`; utility labels `EX_SERVICE_KEY`, `EX_TLS_CERT`) |
| `API_KEY`, `API_SECRET` | test scripts | from `.fixtures.env` |
| `RO_API_KEY`, `RO_API_SECRET` | search, access | from `.fixtures.env` |
| `ID_ENTITY`, `DATA_ENTITY`, `FILE_ENTITY` | test scripts | from `.fixtures.env` |
| `UTILITY_LABEL`, `UTILITY_CERT_LABEL` | utilities | from `.fixtures.env` (`EX_SERVICE_KEY`, `EX_TLS_CERT`) |
| `ADMIN_TOKEN` | validation (definition checks), utilities (list and rotate) | from `.fixtures.env`. Checks are skipped when unset. |
| `MAX_UPLOAD_KB` | validation | `5120`. Set it to your `TSI_PRIVACY_VAULT_MAX_UPLOAD_KB`. |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | erasure | required. Must be a `SYSTEM_ADMIN`. |
| `VIEWER_EMAIL`, `VIEWER_PASSWORD` | erasure | optional. Enables the role check. |

## Running against your own build

`docker-compose.yml` pulls the published image by default, so local source changes
are not running until you build them. To test your working tree, uncomment the
`build:` block under `jetty_app` in `docker-compose.yml`, then:

```bash
mvn clean package -DskipTests
sudo docker compose up -d --build
```

The validation script checks first that the instance enforces entity rules. If it
does not, the script stops and says so.

## Notes

- `.fixtures.env` holds live test secrets. It is git-ignored and written with
  mode 600. Delete it and deactivate the keys when you are done.
- Running setup again is safe. It reuses existing entities, and reuses the saved
  keys while they still work. Set `FORCE=1` to create new keys. A malformed saved
  key from a failed run is discarded and its permission rows are removed.
- If `ADMIN_PASSWORD` is not set, setup asks for it without echoing.
- Content is sent Base64 encoded, the same as the console and the tour.
- The load test lives separately in [`tests/`](../tests/README.md).
