/**
 * Sends one `security-patch` repository_dispatch per finding and resolved line to the
 * repository that runs port-security-patch.yml.
 *
 * Run with
 *   node bin/dispatch-ports.js --findings=new-findings.json --lines=port-lines.json [--dry-run]
 *
 * Environment:
 *   PORT_REPO            owner/repo receiving the dispatch; unset skips dispatching
 *   PORT_DISPATCH_TOKEN  token allowed to dispatch to PORT_REPO (Contents: write)
 *   PORT_BRANCH_MAP      optional JSON {"resolved branch": "target branch"}
 */

const fs = require('fs');

const args = Object.fromEntries(
  process.argv.slice(2).map(arg => {
    const [key, ...value] = arg.replace(/^--/, '').split('=');
    return [key, value.length ? value.join('=') : true];
  })
);

const readJson = (file, fallback) => (file && fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : fallback);

/** Same derivation as the issue's download list: the Solution table's version names the
 *  month, and the line's stem supplies the patch level the version omits. */
const archiveFor = (finding, line) => {
  if (!line.branch || !line.stem) return null;
  if (finding.kind === 'archive') {
    const archive = finding.key.replace(/^patch:/, '');
    return archive.startsWith(`${line.stem}-`) && /^[a-z]{3}-\d{4}$/.test(archive.slice(line.stem.length + 1))
      ? archive
      : null;
  }
  for (const version of finding.fixedVersions || []) {
    const parts = /^(2\.4\.\d+)(?:-p\d+)?-(\d{4})-([a-z]{3})$/i.exec(version);
    if (!parts) continue;
    const prefix = parts[1].replace(/\./g, '-');
    if (line.stem === prefix || line.stem.startsWith(`${prefix}-p`)) {
      return `${line.stem}-${parts[3].toLowerCase()}-${parts[2]}`;
    }
  }
  return null;
};

const main = async () => {
  const report = readJson(args.findings, {findings: []});
  const lines = readJson(args.lines, []);
  const branchMap = JSON.parse(process.env.PORT_BRANCH_MAP || '{}');
  const repo = process.env.PORT_REPO;

  const byTarget = new Map();
  for (const finding of report.findings || []) {
    for (const line of lines) {
      const archive = archiveFor(finding, line);
      if (!archive) continue;
      // Labelled by archive, not finding: an archive usually shows up days before its
      // bulletin, and both name the same patch. The port workflow skips a branch it
      // already pushed, so the bulletin's dispatch then finds the archive's PR.
      const branch = branchMap[line.branch] || line.branch;
      const bulletin = finding.kind === 'bulletin' ? finding.url || '' : '';
      const seen = byTarget.get(`${archive} ${branch}`);
      if (!seen || (!seen.bulletin && bulletin)) {
        byTarget.set(`${archive} ${branch}`, {label: archive, branch, archive, bulletin});
      }
    }
  }
  const dispatches = [...byTarget.values()];

  if (!dispatches.length) {
    console.log('no line has an archive for these findings; nothing to dispatch');
    return;
  }
  if (!repo || args['dry-run']) {
    dispatches.forEach(payload => console.log(`would dispatch to ${repo || '(PORT_REPO unset)'}: ${JSON.stringify(payload)}`));
    return;
  }
  if (!process.env.PORT_DISPATCH_TOKEN) throw new Error('PORT_REPO is set but PORT_DISPATCH_TOKEN is not');

  let failed = 0;
  for (const payload of dispatches) {
    const response = await fetch(`https://api.github.com/repos/${repo}/dispatches`, {
      method: 'POST',
      headers: {
        'user-agent': 'mage-os-security-watch (+https://github.com/mage-os/security-watch)',
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${process.env.PORT_DISPATCH_TOKEN}`,
      },
      body: JSON.stringify({event_type: 'security-patch', client_payload: payload}),
      signal: AbortSignal.timeout(30000),
    });
    if (response.status === 204) {
      console.log(`dispatched to ${repo}: ${JSON.stringify(payload)}`);
    } else {
      failed++;
      console.log(`::error::dispatch to ${repo} failed (HTTP ${response.status}): ${JSON.stringify(payload)}`);
    }
  }
  if (failed) process.exit(1);
};

main().catch(exception => {
  console.error(exception);
  process.exit(1);
});
