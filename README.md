# mage-os/security-watch

Watches upstream for security releases and mirror integrity problems, and turns
what it finds into tracking issues. It changes nothing in any other repository.

Proposed in the multi-release-line RFC. Stages 0 and 1 are useful on their own,
with one supported release line and no policy change.

## Why a separate repository

`mage-os/infrastructure` holds reusable workflows that other repositories consume
via `@main`. This one commits state on most runs, so keeping it here avoids
churning a repository other builds depend on, and lets contributors triage
findings without write access to release infrastructure.

## Ref drift detection

`bin/scan-refs.js` records the tag and branch SHAs of all 32 `mage-os/mirror-*`
repositories and compares them against `state/refs.json` on each run.

This exists because `infrastructure/bin/mirror-sync.sh` runs:

```bash
git push target --all --force
git push target --tags --force
```

with the comment *"Sometimes upstream re-tags a buggy release"*. That is accurate,
and it means an upstream retag rewrites mirror history — changing what an already
published release resolves to — with no record anywhere.

Severity is assigned by what the change implies, not by ref type alone:

| Finding | Severity | Reasoning |
|---|---|---|
| tag moved | critical | Tags are immutable by convention; a moved tag changes a published release |
| tag deleted | critical | A release became unresolvable |
| branch deleted | warning | May be intentional cleanup, but a deleted release branch ends a support line |
| branch moved | info | Branches advance normally |
| new ref | info | Expected on every upstream release |
| mirror unreachable | warning | Transient; the previous baseline is preserved so the next run does not report every ref as new |

Run locally:

```bash
node bin/scan-refs.js                      # compare against committed state
node bin/scan-refs.js --write              # update the baseline
node bin/scan-refs.js --report=drift.json  # machine readable output
```

Exits non-zero only on critical findings, so an unreachable mirror does not page
anyone.

### State is committed, not cached

`actions/cache` evicts after seven days of non-access and is best-effort. A miss
would not degrade gracefully: it would re-report every historical ref as new. A
committed file is auditable, correctable by pull request, and doubles as the
record of when drift was first seen.

The baseline is roughly 120 KB for 1706 refs across 32 mirrors, and a scan takes
about 15 seconds.

## Mirror list

`state/mirrors.json` is extracted from the matrix in
`infrastructure/.github/workflows/sync-upstream-magento.yml` rather than
maintained by hand, so the two cannot drift apart.

## Security release detection

`bin/detect-security.js` polls three independent sources daily and reports
anything absent from `state/seen.json`.

| Source | What it provides | Why it is needed |
|---|---|---|
| `helpx.adobe.com` bulletin index | APSB ids, CVEs, affected and fixed versions, severity | The **only** source that sees the post-July-2026 isolated releases, which are never tagged on public GitHub |
| GitHub Security Advisories | CVE, GHSA id, severity, publication date | Structured metadata, usually same-day |
| Packagist advisories | Composer version constraints | The constraint format needed to decide whether a line is affected |

Findings are keyed by bulletin id where one exists, because a single APSB covers
many CVEs and the project responds per bulletin. CVEs already covered by a
bulletin are folded into it rather than raising separate findings; the source
list records which feeds saw it.

NVD is deliberately not used: its CPE naming returns zero results for modern
Magento.

Measured on a full run: 33 bulletins, 94 GHSA advisories, 484 Packagist
advisories, 390 tracked keys, about 2 seconds.

```bash
node bin/detect-security.js                  # report new findings
node bin/detect-security.js --write          # update state
node bin/detect-security.js --full           # fetch every bulletin page on first run
```

Exits 1 when there are new findings, which is what the workflow gates on.

## Mage-OS has no advisory coverage

`https://packagist.org/api/security-advisories/?packages[]=mage-os/product-community-edition`
returns `{"advisories":[]}`. Packagist does not index the core distribution at
all, so `composer audit` is blind for every Mage-OS install. Publishing GitHub
advisories would not fix this; the repository must serve them itself. See the
RFC for the mechanism.
