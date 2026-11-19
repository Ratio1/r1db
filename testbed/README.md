# Local Multi-Node Testbed

Run the testbed only after the candidate image passes the source/release
contract checks. First it runs the unmodified candidate image as a three-node
secure engine cluster. It then derives a disposable local-only transport image
that adds a repository-built static TCP proxy and replaces only Cloudflared
with a deterministic test adapter; database binary and production entrypoint
hashes must remain equal to the candidate. That phase exercises the complete
Deeploy entrypoint contract. Both phases use the production 500 ms clock-offset
bound, write 10,000 rows, stop/rejoin a member, restart the fleet, validate
persistence, and assert cleanup. The co-located entrypoint phase uses fixed
128 MiB cache and SQL-memory budgets so each member does not independently
reserve a quarter of the entire Docker VM; the unmodified-image phase still
exercises the image defaults.

The entrypoint phase defaults to three nodes. Set `CRDB_TEST_NODE_COUNT=4` to
verify that an explicit four-node configuration converges application ranges
to four voters while retaining the same persistence, failover, and cleanup
checks. Engine-managed system ranges retain their built-in policies.

```bash
python3 -m unittest tests.test_release_contract
testbed/run-local-cluster.sh \
  ghcr.io/ratio1/r1db@sha256:<verified-digest>

CRDB_TEST_NODE_COUNT=4 testbed/run-local-cluster.sh \
  ghcr.io/ratio1/r1db@sha256:<verified-digest>
```

For a pre-publication local image only, set
`R1DB_REQUIRE_DIGEST=false`. The legacy `R1_SQL_REQUIRE_DIGEST` spelling
remains an input alias for existing automation.
Such a run is build feedback and does not satisfy the signed-artifact gate.
The local transport overlay also does not prove Cloudflare behavior. The
unmodified signed digest with real tunnels is required in the hybrid testbed.
Database stores use disposable Docker-managed volumes. This avoids host
bind-mount `fsync` behavior becoming a false R1DB disk-stall failure and
more closely matches the dedicated Linux filesystems used by edge-node fixed
volumes; every harness asserts that its named volumes are deleted on exit.

`run-rolling-upgrade.sh` starts three members from the exact legacy service
digest with persistent stores, validates operator delegation and 10,000 rows,
replaces members one at a time with the candidate, then rolls them back one at
a time. It verifies SQL availability while each member is stopped, full
three-voter replication after each rejoin, unchanged database/entrypoint bytes
in the test transport overlays, and persistence of both operator and delegated
user data.

CI and release use **no Cloudflare account credentials**. Mandatory local
transport tests remain required, and Cloudflare API mocks cover provisioning,
rollback, exact-prefix cleanup and recovery decisions. They also run:

```bash
python3 scripts/quick_tunnel_smoke.py \
  --image ghcr.io/ratio1/r1db@sha256:<verified-digest> \
  --output artifacts/quick-tunnel/result.json --timeout 120
```

The accountless Quick Tunnel HTTP smoke runs the image's embedded cloudflared
against a disposable nonce-only HTTP container on its own Docker bridge. No
ports are published locally, no database endpoint is tunneled, and no account
resources, credentials or DNS records are created by the harness. It removes its
own containers and bridge on exit. `passed` requires an exact public HTTP round
trip. Recognizable provider/network outages are `inconclusive` and explicitly
warned in Actions; they are not proof of working transport. Deterministic image,
fixture, response and local cleanup defects are `failed` and block the workflow.
Results and connector diagnostics are uploaded even on failure. Quick Tunnel
HTTP does not prove named authenticated TCP or account provisioning.

For full named TCP validation **before stable promotion**, run
`run-real-cloudflare-cluster.sh` manually outside Actions with the exact signed
image digest and a dedicated test-only Cloudflare account/zone. It creates three
ephemeral tunnels, places each node on a separate Docker bridge, validates real
replication and failover, audits logs/environments, and removes test resources.
Supply `CF_ACCOUNT_ID`, `CF_ZONE_ID`, `CF_API_TOKEN`, and `CF_BASE_DOMAIN` only
inside that isolated environment, never GitHub Actions or a production account.
The token needs Tunnel edit for the test account and DNS edit/zone read for its
test zone. Retain the result and candidate digest for the promotion decision.

If manual or historical cleanup fails, token files are removed and non-secret
resource IDs remain in `cloudflare-cleanup-state.json`. Reconcile only the exact
run prefix with the existing manual tooling; never guess a production prefix:

```bash
python3 scripts/cloudflare_ephemeral_tunnels.py cleanup \
  --state /path/to/cloudflare-cleanup-state.json \
  --expected-run-prefix r1db-ci-<run-id>-<attempt>
python3 scripts/cloudflare_ephemeral_tunnels.py cleanup-prefix \
  --prefix r1db-ci-<run-id>-<attempt>
```

Supply credentials through the isolated environment, not command arguments.
Verify cleanup completes before destroying that test environment. The old
credentialed Actions recovery workflow has been removed; outstanding historical
resources and stored tokens require administrator cleanup/revocation as described
in `RELEASE.md`.

CI and release also run `scripts/runtime-supervision-smoke.sh` against the
exact candidate. Its scratch-compatible multistage overlay preserves the
candidate database binary and production entrypoint byte-for-byte while adding
only static test transport and fault-injection wrappers. This validates process
supervision and corrupt-store recovery without installing tools into, or
rebuilding, the production image.
