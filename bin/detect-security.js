/**
 * Detects new Magento security releases from three independent sources and
 * reports anything not already recorded in state/seen.json.
 *
 * Since July 2026 Adobe publishes isolated security releases under date-based
 * names (2.4.9-2026-aug) that never reach the public GitHub repository, so tag
 * watching alone misses most security content. The Adobe bulletin index is the
 * only source that sees them.
 *
 * Run with
 *   node bin/detect-security.js [--write] [--report=new.json] [--limit=N]
 */

const fs = require('fs');
const path = require('path');

const args = Object.fromEntries(
  process.argv.slice(2).map(arg => {
    const [key, value] = arg.replace(/^--/, '').split('=');
    return [key, value === undefined ? true : value];
  })
);

const root = path.join(__dirname, '..');
const statePath = path.resolve(root, args.state || 'state/seen.json');

const BULLETIN_INDEX = 'https://helpx.adobe.com/security/products/magento.html';
const BULLETIN_PAGE = id => `https://helpx.adobe.com/security/products/magento/${id}.html`;
const GHSA = 'https://api.github.com/advisories?ecosystem=composer&affects=magento/community-edition&per_page=100';
const PACKAGIST = 'https://packagist.org/api/security-advisories/?packages[]=magento/community-edition&packages[]=magento/product-community-edition';

const USER_AGENT = 'mage-os-security-watch (+https://github.com/mage-os/security-watch)';

const fetchText = async (url, {json = false} = {}) => {
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const response = await fetch(url, {
        headers: {
          'user-agent': USER_AGENT,
          ...(json ? {accept: 'application/json'} : {}),
        },
        signal: AbortSignal.timeout(45000),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return json ? await response.json() : await response.text();
    } catch (exception) {
      if (attempt === 3) {
        console.error(`  fetch failed: ${url} (${exception.message})`);
        return null;
      }
      await new Promise(resolve => setTimeout(resolve, attempt * 2000));
    }
  }
};

const stripTags = html => html.replace(/<[^>]*>/g, ' ').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ').trim();

/** Adobe publishes no feed; every RSS, JSON and CSAF endpoint 404s. The index
 *  page is server rendered, so the bulletin ids can be read straight out of it. */
const fetchBulletinIds = async () => {
  const html = await fetchText(BULLETIN_INDEX);
  if (!html) return [];
  return [...new Set([...html.matchAll(/apsb(\d{2})-(\d+)/gi)].map(m => m[0].toLowerCase()))];
};

const parseBulletin = async (id) => {
  const html = await fetchText(BULLETIN_PAGE(id));
  if (!html) return {id, url: BULLETIN_PAGE(id), cves: [], versions: [], severity: null};

  const text = stripTags(html);
  const cves = [...new Set([...html.matchAll(/CVE-\d{4}-\d{4,7}/g)].map(m => m[0]))];

  // Both the "and earlier" affected versions and the fixed versions appear as
  // bare version tokens; keeping both is enough to decide relevance, and avoids
  // depending on Adobe's table markup staying stable.
  const versions = [...new Set(
    [...text.matchAll(/\b2\.4\.\d+(?:-p\d+|-\d{4}-[a-z]{3})?\b/gi)].map(m => m[0])
  )];

  const severity = ['Critical', 'Important', 'Moderate']
    .find(level => new RegExp(`\\b${level}\\b`).test(text)) || null;

  const published = (text.match(/(?:Date Published|Published)[:\s]+([A-Z][a-z]+ \d{1,2},? \d{4})/) || [])[1] || null;

  return {id, url: BULLETIN_PAGE(id), cves, versions, severity, published};
};

const fetchGhsa = async () => {
  const data = await fetchText(GHSA, {json: true});
  if (!Array.isArray(data)) return [];
  return data
    .filter(entry => entry.cve_id)
    .map(entry => ({
      cve: entry.cve_id,
      ghsa: entry.ghsa_id,
      severity: entry.severity,
      published: entry.published_at,
      url: entry.html_url,
    }));
};

const fetchPackagist = async () => {
  const data = await fetchText(PACKAGIST, {json: true});
  const advisories = data && data.advisories ? data.advisories : {};
  return Object.values(advisories).flat()
    .filter(entry => entry.cve)
    .map(entry => ({
      cve: entry.cve,
      advisoryId: entry.advisoryId,
      affectedVersions: entry.affectedVersions,
      published: entry.reportedAt,
      url: entry.link,
    }));
};

const main = async () => {
  const previous = fs.existsSync(statePath) ? JSON.parse(fs.readFileSync(statePath, 'utf8')) : {};
  const baseline = Object.keys(previous).length === 0;

  console.error('fetching Adobe bulletin index...');
  const bulletinIds = await fetchBulletinIds();
  console.error(`  ${bulletinIds.length} bulletins listed`);

  const unseen = bulletinIds.filter(id => !previous[id]);
  // On a first run every bulletin is unseen; fetching 33 pages to establish a
  // baseline is wasteful when only the ids are needed to seed the state.
  const toFetch = baseline && !args.full ? [] : unseen.slice(0, Number(args.limit) || 25);
  if (toFetch.length) console.error(`fetching ${toFetch.length} new bulletin page(s)...`);

  const bulletins = [];
  for (const id of toFetch) {
    bulletins.push(await parseBulletin(id));
  }

  console.error('fetching GHSA advisories...');
  const ghsa = await fetchGhsa();
  console.error(`  ${ghsa.length} advisories`);

  console.error('fetching Packagist advisories...');
  const packagist = await fetchPackagist();
  console.error(`  ${packagist.length} advisories`);

  // Records are keyed by bulletin id where one exists, because a single APSB
  // covers many CVEs and the project responds per bulletin, not per CVE.
  const records = new Map();
  const cveToBulletin = new Map();

  for (const bulletin of bulletins) {
    records.set(bulletin.id, {
      key: bulletin.id,
      kind: 'bulletin',
      sources: ['adobe'],
      cves: bulletin.cves,
      versions: bulletin.versions,
      severity: bulletin.severity,
      url: bulletin.url,
      published: bulletin.published,
    });
    bulletin.cves.forEach(cve => cveToBulletin.set(cve, bulletin.id));
  }

  const addCveSource = (entry, source) => {
    const bulletinId = cveToBulletin.get(entry.cve);
    if (bulletinId) {
      const record = records.get(bulletinId);
      if (!record.sources.includes(source)) record.sources.push(source);
      return;
    }
    if (previous[entry.cve]) return;
    const existing = records.get(entry.cve);
    if (existing) {
      if (!existing.sources.includes(source)) existing.sources.push(source);
      return;
    }
    records.set(entry.cve, {
      key: entry.cve,
      kind: 'cve',
      sources: [source],
      cves: [entry.cve],
      severity: entry.severity || null,
      affectedVersions: entry.affectedVersions || null,
      url: entry.url,
      published: entry.published,
    });
  };

  ghsa.forEach(entry => addCveSource(entry, 'ghsa'));
  packagist.forEach(entry => addCveSource(entry, 'packagist'));

  const now = new Date().toISOString();
  const findings = [...records.values()];

  const state = {...previous};
  for (const id of bulletinIds) {
    if (!state[id]) state[id] = {firstSeen: now, kind: 'bulletin'};
  }
  for (const finding of findings) {
    if (!state[finding.key]) {
      state[finding.key] = {firstSeen: now, kind: finding.kind, cves: finding.cves};
    }
  }

  if (args.write) {
    fs.mkdirSync(path.dirname(statePath), {recursive: true});
    fs.writeFileSync(statePath, `${JSON.stringify(state, null, 2)}\n`);
  }

  const report = {baseline, tracked: Object.keys(state).length, new: findings.length, findings};
  if (args.report) {
    fs.writeFileSync(path.resolve(root, args.report), `${JSON.stringify(report, null, 2)}\n`);
  }

  if (baseline) {
    console.log(`baseline established: ${Object.keys(state).length} known bulletins, no alerts raised`);
    return 0;
  }

  for (const finding of findings) {
    console.log(
      `${finding.key.padEnd(18)} ${(finding.severity || '-').padEnd(10)} ` +
      `${finding.sources.join('+').padEnd(20)} ${finding.cves.length} CVE(s)  ${finding.url}`
    );
  }
  console.log('');
  console.log(`${findings.length} new finding(s); ${Object.keys(state).length} tracked`);
  return findings.length ? 1 : 0;
};

main().then(code => process.exit(code)).catch(exception => {
  console.error(exception);
  process.exit(3);
});
