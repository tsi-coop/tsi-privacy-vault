# Examples

Runnable scripts for trying the vault and checking its behavior against a live
instance. They use `curl` and `jq` only.

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
| [`scripts/setup/setup-test-fixtures.sh`](scripts/setup/setup-test-fixtures.sh) | Creates an ID, DATA and FILE entity, a read-write key and a read-only key, and writes the credentials to `scripts/setup/.fixtures.env`. |
| [`scripts/store-fetch/test-store-fetch.sh`](scripts/store-fetch/test-store-fetch.sh) | Stores one ID, DATA and FILE record, fetches each back, and compares the value. |
| [`scripts/search/test-blind-index-search.sh`](scripts/search/test-blind-index-search.sh) | Finds a stored record by full value, one word and a 3 character prefix. Checks that case and spacing do not matter. |
| [`scripts/validation/test-entity-validation.sh`](scripts/validation/test-entity-validation.sh) | Regex mismatch, flavor mismatch, MIME type and extension checks, missing file name, size limit, and invalid entity definitions. |
| [`scripts/access/test-access-control.sh`](scripts/access/test-access-control.sh) | Wrong secret, read-only key, key with no grant, unknown entity. |

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
```

The validation script also checks entity definitions through the admin API. It
uses the admin token the setup script saved. The token expires. If those checks fail with HTTP 401, run setup again.

## Environment variables

| Variable | Used by | Default |
|---|---|---|
| `BASE_URL` | all | `http://localhost:8081` |
| `ADMIN_EMAIL` | setup | required |
| `ADMIN_PASSWORD` | setup | prompted when unset |
| `FORCE` | setup | `0`. Set to `1` to create new keys even when saved ones work. |
| `PREFIX` | setup | `EX` (entity codes become `EX_ID_NUMBER`, `EX_NOTE`, `EX_DOCUMENT`) |
| `API_KEY`, `API_SECRET` | test scripts | from `.fixtures.env` |
| `RO_API_KEY`, `RO_API_SECRET` | search, access | from `.fixtures.env` |
| `ID_ENTITY`, `DATA_ENTITY`, `FILE_ENTITY` | test scripts | from `.fixtures.env` |
| `ADMIN_TOKEN` | validation (definition checks) | from `.fixtures.env`. Checks are skipped when unset. |
| `MAX_UPLOAD_KB` | validation | `5120`. Set it to your `TSI_PRIVACY_VAULT_MAX_UPLOAD_KB`. |

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
