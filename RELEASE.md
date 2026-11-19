# Release Process

R1DB releases are produced only by
`.github/workflows/release.yml`. Local builds are development evidence and are
never production signatures.

## Repository Controls

Before the first release, repository administrators must:

1. Protect `main` and require the CI workflow before merge.
2. Create the `release` environment with required reviewers and restrict it to
   the protected `main` branch.
3. Prevent tag deletion or mutation for released tags.
4. Permit the repository workflow to publish the connected GHCR package.
5. Remove the legacy `CF_ACCOUNT_ID`, `CF_ZONE_ID`, `CF_API_TOKEN`, and
   `CF_BASE_DOMAIN` secrets from repository and Actions environments, including
   `release` and `release-cleanup`; revoke the former CI API tokens in Cloudflare.
   Coordinate revocation if a token was shared with another consumer. Remove the
   obsolete `release-cleanup` environment after any outstanding historical
   resource cleanup. These are administrator actions: merging this workflow
   change neither deletes stored secrets nor invalidates previously exposed ones.
   Do not provide Cloudflare credentials to candidate-executing Actions jobs.
   Historical workflow reruns still use their old credential references; revoke
   old tokens and remove stored secrets before retrying those runs.
6. Make the source repository public before merging a `VERSION` change. It may stay
   private while changes are staged and reviewed, but a public image is not
   published from source that anonymous recipients cannot retrieve. Keep the
   corresponding tagged source public for as long as that image is distributed.

Merging a canonical `MAJOR.MINOR.PATCH` change to `VERSION` on `main`
automatically starts the release workflow and derives the immutable `v<version>`
tag. The workflow rejects malformed, unchanged, decreasing, or reused versions.
Manual dispatch has no version input and exists only to resume the current
`VERSION` after an interrupted run. A push-triggered source SHA must remain an
ancestor of current `origin/main`; manual recovery must equal current `main`.
The workflow binds public `main` to `origin/main` and byte-compares the exact
release SHA with an anonymously downloaded source archive before it publishes even an untagged candidate. It
creates no Git or OCI release tag until the candidate has passed validation,
signing, and anonymous digest pull.

The **Release latest signed image** workflow uses one repository-wide concurrency group with its maximum queue,
so release promotion cannot overlap and pending version releases are retained
up to GitHub's concurrency-group limit.

The candidate must pass mandatory local database/API, three-node replication,
persistence, rolling upgrade/rollback, supervision and corrupt-store recovery
tests. Local TCP proxies exercise the production entrypoint; Cloudflare API
mocks exercise provisioning and cleanup without account credentials.

CI and release also run an accountless Quick Tunnel HTTP smoke using the
candidate's own embedded cloudflared and a disposable synthetic HTTP fixture.
No database endpoint is exposed. A verified public round trip is `passed`;
recognizable provider/network unavailability is `inconclusive`, with a workflow
warning and explicit evidence. Image, fixture, unexpected output and local
cleanup defects are `failed` and block publication. External availability does
not bypass any mandatory local test. Quick Tunnel HTTP does not validate named
authenticated TCP tunnels, DNS/account provisioning, or the deployed fleet.
The workflow summary and `quick-tunnel-result.json` release asset report that
scope, candidate identity and outcome; `inconclusive` must never be treated as a
successful real-transport test.
An untagged candidate digest is not a release and must not be used by consumers.
Only a published immutable digest that passes `scripts/verify-image.sh` is an
approved release artifact. Failed candidate digests may remain addressable in
GHCR, but they receive no version tag, source release, or `latest` tag.

Full named TCP validation remains a manual pre-stable requirement on an isolated
testbed with a dedicated test-only Cloudflare account and zone, outside GitHub
Actions. Run `testbed/run-real-cloudflare-cluster.sh` against the exact signed
release digest and retain its result before promoting stable. See
`testbed/README.md`; production credentials must not enter that testbed either.
Historical failed runs may still have resources: use their exact run/attempt
prefix and retained non-secret cleanup state with the manual cleanup tooling.
Removing the automated recovery workflow does not clean historical resources.
An independently controlled automated named-tunnel validator is future work.

## First Package Publication

GHCR package visibility is separate from repository visibility. The workflow
builds the candidate once and publishes it only by immutable digest, with no
human-facing tag. It tests and scans that exact registry digest, then signs and
attests it.

GitHub does not expose a supported API for changing a package's visibility.
After the source repository is public, a package administrator must open the
`r1db` package settings and set **Package visibility** to
**Public**. The first release run is expected to stop at the anonymous-pull
gate after creating the package. Change visibility in the GitHub UI and manually
dispatch the workflow again from `main`; no source or OCI version tag has been created at that
point. Later releases need no visibility action.

Do not make the package public while the source repository is private. The
workflow uses a fresh empty Docker credential directory to anonymously
pull the exact signed digest before it prepares a draft GitHub release/source
tag, creates the single immutable version image tag, publishes the release,
and updates `latest` last.
A version collision fails closed instead of moving an existing identifier.
If a run stops between those promotion steps, the next run may resume only
when the existing source tag resolves to the same source commit and the
existing OCI version tag resolves to the same candidate digest. Any mismatch
fails closed.

## Release Channels

`latest` identifies the newest successfully published release. Only the
**Release latest signed image** workflow moves it, after every release gate and
publication step succeeds.

`stable` identifies the release selected for Ratio1 Deeploy. Dispatch
**Promote stable image** from `main`, enter an exact published `vMAJOR.MINOR.PATCH`
tag, and approve the protected `release` environment. The workflow rejects
drafts and prereleases, checks the release's canonical `image-reference.txt`,
requires the immutable version tag to resolve to that digest, and reruns
`scripts/verify-image.sh` before moving `stable`. Promotions are serialized and
the previous and resulting digests are recorded in the run summary. Roll back
by promoting an earlier published version through the same workflow.

`stable` is deliberately mutable. Deeploy uses it with an always-pull policy,
so different nodes can adopt a promotion at different restart times. Promote
only versions that have completed the required Deeploy local and hybrid
validation; use an immutable digest wherever staggered restart adoption is not
acceptable.

## Evidence

Each GitHub release contains the immutable image reference, source and image
SPDX/CycloneDX SBOMs, source hashes, provenance, notices, the exact Debian
corresponding-source bundle, and the Ratio1 patch record. GitHub's source
archive for the immutable tag is publicly available,
and the release records the SHA-256 of the anonymously downloaded pre-release
source archive. The image digest also carries GitHub provenance and SPDX attestations
and a separate keyless Cosign signature bound to the exact release workflow on
protected `main`. The reviewed OpenVEX document is attached as a digest-bound
Cosign attestation.

Consumers verify a release with:

```bash
scripts/verify-image.sh \
  ghcr.io/ratio1/r1db@sha256:<digest> \
  v1.0.7
```

Do not move an existing version tag. Publish a new patch tag and document
superseded or revoked digests in its release notes.
