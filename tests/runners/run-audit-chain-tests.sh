#!/usr/bin/env bash
# Runs the audit chain tests against a throwaway PostgreSQL container with db/*.sql applied.
set -euo pipefail
export TEST_CLASS=AuditChainPostgresTest
exec "$(dirname "$0")/run-erasure-tests.sh"
