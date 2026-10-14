/**
 * Resolves each supported Mage-OS release line to the mageos-magento2 branch a
 * security port must target, and to the Adobe archive stem that line is built on.
 *
 * Run with
 *   node bin/resolve-lines.js --matrix=<supported-version matrix JSON> [--repo=mage-os/mageos-magento2]
 *
 * Prints a JSON array: [{line, version, upstream, stem, branch, note}].
 */

const fs = require('fs');
const path = require('path');

const args = Object.fromEntries(
  process.argv.slice(2).map(arg => {
    const [key, ...value] = arg.replace(/^--/, '').split('=');
    return [key, value.length ? value.join('=') : true];
  })
);

const REPO = args.repo || 'mage-os/mageos-magento2';
const LINES_PATH = path.join(__dirname, '..', 'state', 'patch-lines.json');
const USER_AGENT = 'mage-os-security-watch (+https://github.com/mage-os/security-watch)';

const api = async (route) => {
  const response = await fetch(`https://api.github.com/repos/${REPO}/${route}`, {
    headers: {
      'user-agent': USER_AGENT,
      accept: 'application/vnd.github+json',
      ...(process.env.GITHUB_TOKEN ? {authorization: `Bearer ${process.env.GITHUB_TOKEN}`} : {}),
    },
    signal: AbortSignal.timeout(30000),
  });
  if (response.status === 404 || response.status === 422) return null;
  if (!response.ok) throw new Error(`${route}: HTTP ${response.status}`);
  return response.json();
};

const compareVersions = (a, b) => {
  const [x, y] = [a, b].map(v => v.split(/[.-]/).map(n => (/^\d+$/.test(n) ? Number(n) : n)));
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    if (x[i] === y[i]) continue;
    if (x[i] === undefined) return -1;
    if (y[i] === undefined) return 1;
    return x[i] < y[i] ? -1 : 1;
  }
  return 0;
};

/** Hardcoding branch names failed twice: the runbook said `main,release/3.x` while
 *  upstream release/3.x sat untouched from 2026-05-17 and every 3.x release was cut
 *  from main. The tag is the ground truth. A release tag sits on a generated
 *  "Release X" commit whose parent is the source commit, so the line's branch is the
 *  one containing that parent. A `release/<major>.x` that contains it wins over main,
 *  because once a line branch is cut and released from, ports belong there.
 *
 *  Containment alone is not enough for main: main contains the source of every old
 *  release, so 2.2.2 resolved to main although main now builds 3.x. Main is a
 *  candidate only for the newest released major. */
const resolveBranch = async (version, major, branches, newestMajor) => {
  const tagCommit = await api(`commits/${encodeURIComponent(version)}`);
  if (!tagCommit) return {branch: null, note: `tag ${version} not found in ${REPO}`};
  const source = tagCommit.parents[0] && tagCommit.parents[0].sha;
  if (!source) return {branch: null, note: `tag ${version} has no parent commit`};

  const candidates = [`release/${major}.x`, ...(Number(major) === newestMajor ? ['main'] : [])]
    .filter(name => branches.includes(name));
  for (const branch of candidates) {
    const comparison = await api(`compare/${source}...${encodeURIComponent(branch)}`);
    if (comparison && ['identical', 'ahead'].includes(comparison.status)) {
      return {branch, note: null};
    }
  }
  return {
    branch: null,
    note: `no release/${major}.x containing ${version}; cut one from ${source.slice(0, 11)}, the source commit of ${version}`,
  };
};

const main = async () => {
  const raw = args.matrix && fs.existsSync(args.matrix) ? fs.readFileSync(args.matrix, 'utf8') : args.matrix;
  const matrix = JSON.parse(raw || '{}');

  // One entry per major: the newest release is the one a port must reach.
  const newest = new Map();
  for (const entry of matrix.include || []) {
    const version = String(entry.magento || '').split(':')[1];
    if (!version || !/^\d+\.\d+\.\d+/.test(version)) continue;
    const major = version.split('.')[0];
    const current = newest.get(major);
    if (!current || compareVersions(version, current.version) > 0) {
      newest.set(major, {version, upstream: entry.upstream || null});
    }
  }

  const stems = fs.existsSync(LINES_PATH) ? JSON.parse(fs.readFileSync(LINES_PATH, 'utf8')).stems || [] : [];
  const branches = (await api('branches?per_page=100') || []).map(branch => branch.name);

  // The newest major with a release tag, whatever the supported data says, so a line
  // dropped from support cannot make main look like it still builds an older major.
  let newestMajor = 0;
  for (let page = 1; page <= 10; page++) {
    const tags = await api(`tags?per_page=100&page=${page}`) || [];
    for (const {name} of tags) {
      if (/^\d+\.\d+\.\d+$/.test(name)) newestMajor = Math.max(newestMajor, Number(name.split('.')[0]));
    }
    if (tags.length < 100) break;
  }

  const lines = [];
  for (const [major, {version, upstream}] of [...newest].sort((a, b) => Number(b[0]) - Number(a[0]))) {
    const stem = upstream ? upstream.replace(/\./g, '-') : null;
    const resolved = await resolveBranch(version, major, branches, newestMajor);
    lines.push({
      line: `${major}.x`,
      version,
      upstream,
      stem: stem && stems.includes(stem) ? stem : null,
      branch: resolved.branch,
      note: resolved.note || (stem && !stems.includes(stem) ? `no ${stem} stem in state/patch-lines.json` : null),
    });
  }

  console.log(JSON.stringify(lines, null, 2));
};

main().catch(exception => {
  console.error(exception);
  process.exit(1);
});
