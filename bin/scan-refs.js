/**
 * Records the tag and branch SHAs of every mage-os mirror and reports changes
 * against the committed state.
 *
 * infrastructure/bin/mirror-sync.sh force-pushes both tags and branches on every
 * sync, with the comment "Sometimes upstream re-tags a buggy release". When that
 * happens the mirror's history is rewritten and nothing currently records it.
 *
 * Run with
 *   node bin/scan-refs.js [--state=state/refs.json] [--report=drift.json] [--write]
 */

const fs = require('fs');
const path = require('path');
const {execFileSync} = require('child_process');

const args = Object.fromEntries(
  process.argv.slice(2).map(arg => {
    const [key, value] = arg.replace(/^--/, '').split('=');
    return [key, value === undefined ? true : value];
  })
);

const root = path.join(__dirname, '..');
const statePath = path.resolve(root, args.state || 'state/refs.json');
const mirrorsPath = path.resolve(root, args.mirrors || 'state/mirrors.json');

const mirrors = JSON.parse(fs.readFileSync(mirrorsPath, 'utf8'));
const previous = fs.existsSync(statePath)
  ? JSON.parse(fs.readFileSync(statePath, 'utf8'))
  : {};

const lsRemote = (repo) => {
  const url = `https://github.com/mage-os/mirror-${repo}.git`;
  let output;
  try {
    output = execFileSync('git', ['ls-remote', '--tags', '--heads', url], {
      encoding: 'utf8',
      maxBuffer: 1024 * 1024 * 64,
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 120000,
    });
  } catch (exception) {
    return null;
  }

  const refs = {};
  for (const line of output.split('\n')) {
    const match = line.match(/^([0-9a-f]{40})\s+(refs\/(?:tags|heads)\/.+)$/);
    if (!match) continue;
    // Annotated tags list a second ^{} entry pointing at the commit. The tag
    // object is the identity that matters for drift, so the peeled entry is
    // dropped rather than overwriting it.
    if (match[2].endsWith('^{}')) continue;
    refs[match[2]] = match[1];
  }
  return refs;
};

const findings = [];
const current = {};
let unreachable = 0;

for (const repo of mirrors) {
  const refs = lsRemote(repo);
  if (refs === null) {
    unreachable++;
    findings.push({repo, severity: 'warning', kind: 'unreachable', ref: '-'});
    // Preserve the last known state so a transient network failure does not
    // erase the baseline and report every ref as new on the next run.
    if (previous[repo]) current[repo] = previous[repo];
    continue;
  }

  current[repo] = refs;
  const before = previous[repo];
  if (!before) {
    findings.push({repo, severity: 'info', kind: 'baseline', ref: `${Object.keys(refs).length} refs`});
    continue;
  }

  for (const [ref, sha] of Object.entries(refs)) {
    const isTag = ref.startsWith('refs/tags/');
    if (!(ref in before)) {
      findings.push({repo, severity: 'info', kind: 'new', ref, sha});
    } else if (before[ref] !== sha) {
      // Branches advance legitimately; tags are supposed to be immutable.
      findings.push({
        repo,
        severity: isTag ? 'critical' : 'info',
        kind: isTag ? 'tag-moved' : 'branch-moved',
        ref,
        from: before[ref],
        to: sha,
      });
    }
  }

  for (const ref of Object.keys(before)) {
    if (ref in refs) continue;
    findings.push({
      repo,
      severity: ref.startsWith('refs/tags/') ? 'critical' : 'warning',
      kind: 'deleted',
      ref,
      from: before[ref],
    });
  }
}

if (args.write) {
  fs.mkdirSync(path.dirname(statePath), {recursive: true});
  fs.writeFileSync(statePath, `${JSON.stringify(current, null, 2)}\n`);
}

const critical = findings.filter(f => f.severity === 'critical');
const report = {
  scanned: mirrors.length,
  unreachable,
  critical: critical.length,
  findings,
};

if (args.report) {
  fs.writeFileSync(path.resolve(root, args.report), `${JSON.stringify(report, null, 2)}\n`);
}

const label = {critical: 'CRITICAL', warning: 'warning', info: 'info'};
for (const finding of findings) {
  if (finding.kind === 'branch-moved' || finding.kind === 'new') continue;
  const detail = finding.from && finding.to
    ? `${finding.from.slice(0, 8)} -> ${finding.to.slice(0, 8)}`
    : finding.from ? `was ${finding.from.slice(0, 8)}` : finding.ref;
  console.log(`${label[finding.severity].padEnd(9)} ${finding.repo.padEnd(38)} ${finding.kind.padEnd(13)} ${finding.ref === '-' ? '' : finding.ref} ${detail === finding.ref ? '' : detail}`);
}

console.log('');
console.log(`scanned ${mirrors.length} mirrors, ${unreachable} unreachable, ${critical.length} critical`);

// A non-zero exit is what the workflow keys its alerting off, so transient
// unreachability must not trip it.
process.exit(critical.length ? 1 : 0);
