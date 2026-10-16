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

`bin/detect-security.js` polls four independent sources hourly and reports
anything absent from `state/seen.json`.

Cadence was daily until 2026-09-08, on the reasoning that upstream ships monthly.
Out-of-band bulletins break that: APSB26-146 arrived on a Monday afternoon. Worse,
GitHub does not honour the declared minute. Across the ten scheduled runs before the
change it started the workflow a median of 4.2h late, worst case 7.2h, never sooner
than 3.0h, so a daily slot meant up to ~31h of latency. Hourly does not fix the drift;
it bounds the damage, because a dropped slot is retried within the hour.

### Polling

`.github/workflows/poll.yml` runs `bin/poll.sh`: one job that runs the detector every 10 minutes for 330 minutes, then dispatches its own successor. It dispatches `detect-security.yml` only when the detector reports new findings, so quiet polls create no runs.

| Fact | Detail |
|---|---|
| Why not cron | On 2026-10-13 the hourly cron ran 3 times in 24h, 7-8h apart. Archives live at 15:24Z were first seen at 17:59Z |
| Why the chain works | `GITHUB_TOKEN` cannot trigger workflows, except via `workflow_dispatch` and `repository_dispatch` |
| Duplicate pollers | Prevented by `concurrency: poll`; extra triggers wait as the single pending run |
| Chain break | Watchdog cron `23 */2 * * *` restarts it; a failed handoff also fails the run |
| Retry | The same findings are re-dispatched after 60 minutes if the pipeline has not recorded them |
| Stop | `gh workflow disable poll.yml` |
| Test | `gh workflow run poll.yml -f minutes=6 -f interval=3` |

The hourly cron in `detect-security.yml` stays as a backup and as the cadence for the `health` check.

| Source | What it provides | Why it is needed |
|---|---|---|
| Adobe bulletin collection (CaaS API) + `helpx.adobe.com/security/products/magento.html` | APSB ids, CVEs, affected and fixed versions, severity | The **only** source that sees the post-July-2026 isolated releases, which are never tagged on public GitHub |
| GitHub Security Advisories | CVE, GHSA id, severity, publication date | Structured metadata, usually same-day |
| Packagist advisories | Composer version constraints | The constraint format needed to decide whether a line is affected |
| `repo.magento.com/patch/` probe | The archive itself, before anything describes it | The only source independent of Adobe's bulletin process. On 2026-09-08 the September archives were live while no bulletin existed on either index and both advisory feeds were empty |

Findings are keyed by bulletin id where one exists, because a single APSB covers
many CVEs and the project responds per bulletin. CVEs already covered by a
bulletin are folded into it rather than raising separate findings; the source
list records which feeds saw it.

NVD is deliberately not used: its CPE naming returns zero results for modern
Magento.

### Probing the patch archives

The first three sources all derive from a bulletin, so they see nothing until Adobe
publishes one. Archive names do not depend on that: they are
`repo.magento.com/patch/<stem>-<mon>-<year>.zip`, and a `HEAD` says whether a release
exists. October 2026 answers 404 across every stem, so a 200 is a real signal.

The stems live in `state/patch-lines.json` and carry the upstream patch level, which
the bulletin's own solution version omits: September's archive for the 2.4.8 line is
`2-4-8-p5-sep-2026.zip`, while the bulletin calls that version `2.4.8-2026-sep`.
Deriving a URL from the bulletin token alone yields `2-4-8-sep-2026.zip`, which 404s.

That list needs updating whenever Adobe cuts a new p-release for a line, so each run
also probes the previous month, whose archives are known to exist. Zero hits there
means the list has rotted, and the run says so rather than going quiet.

Measured on a full run: 34 bulletins, 356 GHSA advisories, 484 Packagist
advisories, 393 tracked keys, about 4 seconds.

### Which index is read

Bulletin ids come from Adobe's Content-as-a-Service collection, filtered to card links
under `products/commerce/` or `products/magento/`:

```
https://www.adobe.com/chimera-api/collection?originSelection=hawks&contentTypeTags=caas%3Acontent-type%2Fdocumentation&complexQuery=(("caas:trust-center/security-bulletin"))&language=en&country=us&draft=false&size=1000&flatFile=false
```

| Fact | Detail |
|---|---|
| Why the API, not the page | `security-bulletin.html` now redirects to `adobe.com/trust/security/bulletins-and-advisories.html`, a client-rendered shell with no bulletin links. Regexing it yielded zero ids from at least 2026-09-30, and APSB26-153 (2026-10-13) went undetected |
| `originSelection=hawks` | Required. Without it the API returns an 8-card sample |
| Scope | Current calendar year, 120 cards across all products on 2026-10-13. Older bulletins are already in `state/seen.json` |
| Bulletin pages | New bulletins live at `www.adobe.com/trust/security/products/commerce/<id>.html` and have no helpx page; the card link is used as-is |

The per-product page `security/products/magento.html` is read too and unioned in. It
cannot be primary because it lags: APSB26-146 was missing from it more than 24 hours
after publication, and APSB26-153 was absent the day it shipped.

### Degraded sources fail the run

A source that returns nothing looks like a quiet month. Each of these is recorded in
the report's `degraded` list, and the `health` job fails the workflow run on it:

| Source | Degraded when |
|---|---|
| Bulletin collection | Unreachable, or no Commerce cards |
| Per-product index | Unreachable, or no bulletin ids on the page |
| Bulletin page | A new bulletin's page is unreachable (it is still reported, without CVEs) |
| GHSA, Packagist | Zero advisories |
| Patch archives | Zero previous-month hits (stale stem list) |

`track` and `record` still run on what the healthy sources found. The script exits 2
when any source is degraded, otherwise 1 on new findings and 0 on none.

```bash
node bin/detect-security.js                  # report new findings
node bin/detect-security.js --write          # update state
node bin/detect-security.js --full           # fetch every bulletin page on first run
```

The workflow gates on the report's `new` and `degraded` counts, not the exit code.

### Port targets in the tracking issue

Each issue lists one checklist row and one apply command per supported line. Branches are resolved when the issue opens, by `bin/resolve-lines.js`; none are written into the template.

| Step | Rule |
|---|---|
| Supported lines | `mage-os/github-actions/supported-version`, `kind: currently-supported`; newest release per major |
| Branch | The branch containing the parent of that release's tag (the tag sits on a generated "Release X" commit). `release/<major>.x` first; `main` only for the newest released major |
| Patch | The line's `upstream` version mapped to a stem in `state/patch-lines.json`. Archive issues list only lines built on that archive's stem; bulletin downloads list only stems some line uses |
| Unresolved | The row names the commit to cut `release/<major>.x` from |

Resolved on 2026-10-14: `3.x (3.6.0, upstream 2.4.9) → main`. Upstream `release/3.x` has not moved since 2026-05-17 and does not contain 3.6.0, and `release/4.x` has no release, so neither is a target.

```bash
GITHUB_TOKEN=$(gh auth token) node bin/resolve-lines.js \
  --matrix='{"include":[{"magento":"mage-os/project-community-edition:3.6.0","upstream":"2.4.9"}]}'
```

### Port PRs

After the issues open, `track` sends one `security-patch` repository_dispatch per new finding and resolved line to `PORT_REPO`. That repository's `port-security-patch.yml` ports the archive to the line branch and opens a PR: ready when it applied cleanly, a draft otherwise. Merging stays with maintainers.

| Setting | Kind | Purpose |
|---|---|---|
| `PORT_REPO` | variable | `owner/repo` receiving the dispatch. Unset disables dispatching |
| `PORT_APP_ID`, `PORT_APP_PRIVATE_KEY` | variable, secret | GitHub App that mints the dispatch token. Used when `PORT_APP_ID` is set |
| `PORT_DISPATCH_TOKEN` | secret | Fallback token when no App is configured. Fine-grained, `PORT_REPO` only, Contents: read and write |
| `PORT_BRANCH_MAP` | variable | JSON `{"resolved": "target"}` to redirect a branch, e.g. for a rehearsal |

| Rule | Detail |
|---|---|
| Payload | `{label, branch, archive, bulletin}`; `label` is the archive name |
| One PR per archive and branch | An archive is usually detected days before its bulletin. Both dispatch the same label, and the port workflow skips a `security/<label>-<branch>` branch that already exists |
| Hotfix bulletins | No archive is derivable, so nothing is dispatched; port from the issue runbook |
| Failure | Fails `track`, so state is not recorded and the next run retries |

Check a dispatch without sending it:

```bash
PORT_REPO=mage-os/mageos-magento2 node bin/dispatch-ports.js \
  --findings=new-findings.json --lines=port-lines.json --dry-run
```

#### Demonstration setup (current)

| Setting | Value |
|---|---|
| `PORT_REPO` | `melindash/mageos-magento2` |
| `PORT_BRANCH_MAP` | `{"main":"rehearsal/3.x"}`. Fork `main` already carries October, so ports land on a branch cut before it |
| `PORT_DISPATCH_TOKEN` | Fine-grained token owned by a maintainer, scoped to the fork. Demonstration only: production must not depend on a personal token |

#### Moving to mage-os

1. Merge `port-security-patch.yml` and `.github/scripts/port-security-patch.sh` into `mage-os/mageos-magento2` from the `ci/port-security-patch` branch of `melindash/mageos-magento2`. Rebase it onto current `main` first. Once mage-os/generate-mirror-repo-js#356 merges, set `PORTER_REPO: mage-os/generate-mirror-repo-js` and pin `PORTER_REF` to the merge commit.
2. Rehearse it there with **Run workflow** against a throwaway branch before enabling dispatch.
3. Create a GitHub App in the `mage-os` org with repository permission **Contents: read and write**, and install it on `mage-os/mageos-magento2`. This repository must be in the same org: the token is minted for this repository's owner.
4. In `mage-os/security-watch` settings:

   ```bash
   gh variable set PORT_APP_ID -R mage-os/security-watch --body <app id>
   gh secret set PORT_APP_PRIVATE_KEY -R mage-os/security-watch < app-private-key.pem
   gh variable set PORT_REPO -R mage-os/security-watch --body mage-os/mageos-magento2
   gh variable delete PORT_BRANCH_MAP -R mage-os/security-watch
   gh secret delete PORT_DISPATCH_TOKEN -R mage-os/security-watch
   ```

5. Revoke the demonstration token and unset `PORT_REPO` on `melindash/security-watch`, so two watchers do not dispatch to two repositories.
6. Optional: PRs opened with `GITHUB_TOKEN` do not trigger CI. To run CI on port PRs, give `port-security-patch.yml` an App token for `gh pr create` as well.

## Mage-OS has no advisory coverage

`https://packagist.org/api/security-advisories/?packages[]=mage-os/product-community-edition`
returns `{"advisories":[]}`. Packagist does not index the core distribution at
all, so `composer audit` is blind for every Mage-OS install. Publishing GitHub
advisories would not fix this; the repository must serve them itself. See the
RFC for the mechanism.
