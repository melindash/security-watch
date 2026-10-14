/**
 * Detects new Magento security releases from four independent sources and
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

// The cross-product index page (helpx security-bulletin.html, now redirecting to
// adobe.com/trust/security/bulletins-and-advisories.html) became a client-rendered
// shell by 2026-09-30 and has listed no bulletin links since. Its cards come from this
// Content-as-a-Service query, read here directly. `originSelection=hawks` is required;
// without it the API silently returns an 8-card sample.
const BULLETIN_INDEX = 'https://www.adobe.com/chimera-api/collection?originSelection=hawks'
  + '&contentTypeTags=caas%3Acontent-type%2Fdocumentation'
  + `&complexQuery=${encodeURIComponent('(("caas:trust-center/security-bulletin"))')}`
  + '&language=en&country=us&draft=false&size=1000&flatFile=false';
const PRODUCT_INDEX = 'https://helpx.adobe.com/security/products/magento.html';
const BULLETIN_PAGE = id => `https://helpx.adobe.com/security/products/magento/${id}.html`;
const GHSA = 'https://api.github.com/advisories?ecosystem=composer&affects=magento/community-edition&per_page=100';
const PACKAGIST = 'https://packagist.org/api/security-advisories/?packages[]=magento/community-edition&packages[]=magento/product-community-edition';

const ARCHIVE = (stem, month) => `https://repo.magento.com/patch/${stem}-${month}.zip`;
const LINES_PATH = path.resolve(root, args.lines || 'state/patch-lines.json');

const USER_AGENT = 'mage-os-security-watch (+https://github.com/mage-os/security-watch)';

/** A source that returns nothing is indistinguishable from a quiet month unless it is
 *  reported. The cross-product index yielded zero ids for two weeks and the only trace
 *  was a log line nobody reads, so APSB26-153 went undetected. Every degraded source
 *  lands in the report, and the workflow fails the run on it. */
const degraded = [];
const degrade = (source, reason) => {
  console.error(`  WARNING: ${source}: ${reason}`);
  degraded.push({source, reason});
};

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

/** fetchText discards headers, and rel=next is the only way to page the advisories API. */
const fetchJson = async (url) => {
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const response = await fetch(url, {
        headers: {
          'user-agent': USER_AGENT,
          accept: 'application/json',
          ...(process.env.GITHUB_TOKEN ? {authorization: `Bearer ${process.env.GITHUB_TOKEN}`} : {}),
        },
        signal: AbortSignal.timeout(45000),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const next = (/<([^>]+)>;\s*rel="next"/.exec(response.headers.get('link') || '') || [])[1] || null;
      return {data: await response.json(), next};
    } catch (exception) {
      if (attempt === 3) {
        console.error(`  fetch failed: ${url} (${exception.message})`);
        return null;
      }
      await new Promise(resolve => setTimeout(resolve, attempt * 2000));
    }
  }
};

const headOk = async (url) => {
  try {
    const response = await fetch(url, {
      method: 'HEAD',
      headers: {'user-agent': USER_AGENT},
      signal: AbortSignal.timeout(30000),
    });
    return response.status === 200;
  } catch (exception) {
    return null;
  }
};

/** The archive is a few KB, so reading its listing costs little and saves the reader
 *  a step the runbook could otherwise only describe as "take the -CE.patch". Only the
 *  central directory is parsed; no patch body is read, stored or redistributed. */
const archiveEntries = async (url) => {
  try {
    const response = await fetch(url, {headers: {'user-agent': USER_AGENT}, signal: AbortSignal.timeout(60000)});
    if (!response.ok) return [];
    const buffer = Buffer.from(await response.arrayBuffer());
    const names = [];
    for (let i = 0; i < buffer.length - 4; i++) {
      if (buffer.readUInt32LE(i) !== 0x02014b50) continue;
      const nameLength = buffer.readUInt16LE(i + 28);
      const extra = buffer.readUInt16LE(i + 30);
      const comment = buffer.readUInt16LE(i + 32);
      names.push(buffer.toString('utf8', i + 46, i + 46 + nameLength));
      i += 45 + nameLength + extra + comment;
    }
    return names.filter(name => name.endsWith('.patch') && !name.startsWith('__MACOSX'));
  } catch (exception) {
    console.error(`  could not read archive listing: ${url} (${exception.message})`);
    return [];
  }
};

const monthStamp = (date) => {
  const month = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
  return `${month[date.getUTCMonth()]}-${date.getUTCFullYear()}`;
};

/** The fourth source, and the only one that owes nothing to Adobe's bulletin process.
 *  On 2026-09-08 the September archives were live while no bulletin existed on either
 *  index and neither GHSA nor Packagist had anything, so every other source was blind
 *  by construction. Archive names are predictable, so they can be probed directly.
 *
 *  The previous month is probed as well, purely as a staleness check: those archives
 *  are known to exist, so zero hits there means the stem list has rotted past a new
 *  p-release and this source has gone quiet without failing. */
const fetchArchives = async (seen) => {
  if (!fs.existsSync(LINES_PATH)) {
    console.error(`  no ${LINES_PATH}; archive probing skipped`);
    return [];
  }

  const stems = JSON.parse(fs.readFileSync(LINES_PATH, 'utf8')).stems || [];
  const now = new Date();
  const previous = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1));
  const [current, prior] = [monthStamp(now), monthStamp(previous)];

  const found = [];
  let priorHits = 0;

  for (const stem of stems) {
    const key = `patch:${stem}-${current}`;
    // HEAD every poll, GET only until the stem is recorded, so steady state stays cheap.
    if (!seen[key] && await headOk(ARCHIVE(stem, current))) {
      const url = ARCHIVE(stem, current);
      const entries = await archiveEntries(url);
      found.push({
        key,
        stem,
        month: current,
        url,
        entries,
        cePatch: entries.find(name => /-CE\.patch$/.test(name)) || null,
      });
    }
    if (await headOk(ARCHIVE(stem, prior))) priorHits++;
  }

  if (stems.length && priorHits === 0) {
    degrade('patch archives', `no ${prior} archive matched any stem in ${LINES_PATH}; the list is probably stale`);
  }

  return found;
};

const stripTags = html => html.replace(/<[^>]*>/g, ' ').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ').trim();

/** Adobe publishes no feed; every RSS, JSON and CSAF endpoint 404s. Two listings are
 *  read and unioned, so either one breaking degrades to partial coverage, and the
 *  break itself is reported rather than logged.
 *
 *  The CaaS collection is primary because the per-product page lags it. APSB26-146 was
 *  missing from products/magento.html a day after publication, and APSB26-153
 *  (2026-10-13) was in the collection while that page still stopped at 146. Bulletins
 *  now live under products/commerce/ on www.adobe.com; the older magento/ path is
 *  matched too. The card link is kept because a new bulletin has no helpx page at all:
 *  helpx magento/apsb26-153.html 404s. */
const fetchBulletinIds = async () => {
  const ids = new Set();
  const urls = new Map();

  const collection = await fetchText(BULLETIN_INDEX, {json: true});
  const cards = collection && Array.isArray(collection.cards) ? collection.cards : null;
  if (!cards) {
    degrade('bulletin collection', 'unreachable or not a card list');
  } else {
    for (const card of cards) {
      const match = /\/products\/(?:commerce|magento)\/(apsb\d{2}-\d+)/i.exec(card.overlayLink || '');
      if (!match) continue;
      const id = match[1].toLowerCase();
      ids.add(id);
      urls.set(id, `${card.overlayLink.replace(/\.html$/, '')}.html`);
    }
    if (ids.size === 0) degrade('bulletin collection', `${cards.length} cards, none for Commerce`);
  }

  const product = await fetchText(PRODUCT_INDEX);
  if (!product) {
    degrade('per-product index', 'unreachable');
  } else {
    const before = ids.size;
    const found = [...product.matchAll(/apsb\d{2}-\d+/gi)].map(match => match[0].toLowerCase());
    found.forEach(id => ids.add(id));
    if (found.length === 0) degrade('per-product index', 'page fetched but listed no bulletins');
    if (ids.size > before) console.error(`  per-product index added ${ids.size - before} id(s) the collection lacks`);
  }

  return {ids: [...ids], urls};
};

const parseBulletin = async (id, url = BULLETIN_PAGE(id)) => {
  const html = await fetchText(url);
  if (!html) {
    degrade('bulletin page', `${url} unreachable; ${id} reported without CVEs`);
    return {id, url, cves: [], versions: [], fixedVersions: [], hotfixUrl: null, severity: null};
  }

  const text = stripTags(html);
  const cves = [...new Set([...html.matchAll(/CVE-\d{4}-\d{4,7}/g)].map(m => m[0]))];

  const VERSION = /\b2\.4\.\d+(?:-p\d+|-\d{4}-[a-z]{3}|-(?:alpha|beta|rc)\d+)?\b/gi;

  // Both the "and earlier" affected versions and the fixed versions appear as
  // bare version tokens; keeping both is enough to decide relevance, and avoids
  // depending on Adobe's table markup staying stable.
  const versions = [...new Set([...text.matchAll(VERSION)].map(m => m[0]))];

  // Relevance is one thing, telling someone what to download is another, and for
  // that the two lists must not be conflated. APSB26-146 lists 2.4.9-2026-aug and
  // five more under Affected Versions and ships no isolated release at all, so
  // deriving download URLs from the whole page pointed at the vulnerable builds.
  // Only the Solution table names what actually fixes it.
  const solutionStart = text.search(/\bSolution\b/);
  const solutionEnd = text.search(/\bVulnerability Details\b/);
  const solution = solutionStart >= 0 && solutionEnd > solutionStart
    ? text.slice(solutionStart, solutionEnd)
    : '';
  // The Solution table has one row per product, and Adobe Commerce carries lines that
  // Open Source no longer gets: APSB26-153 fixes 2.4.4-2.4.6 for Commerce only, and
  // their public archives 404. Mage-OS builds from Open Source, so that row wins when
  // present. The row is the product name followed directly by a version, which skips
  // the prose note above the table that also names the product.
  const openSource = (/Magento Open Source\s+(2\.4\..*?)(?:Release notes|$)/.exec(solution) || [])[1] || '';
  const fixedFrom = VERSION.test(openSource) ? openSource : solution;
  VERSION.lastIndex = 0;
  const fixedVersions = [...new Set([...fixedFrom.matchAll(VERSION)].map(m => m[0]))];

  // A bulletin with no version in its Solution table is fixed by a hotfix instead,
  // distributed under its own name and reachable only through the linked notes.
  const hotfixUrl = ([...html.matchAll(/<a[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/gi)]
    .map(match => [match[1], match[2].replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim()])
    .find(([, label]) => /hotfix/i.test(label)) || [])[0] || null;

  const severity = ['Critical', 'Important', 'Moderate']
    .find(level => new RegExp(`\\b${level}\\b`).test(text)) || null;

  // The date sits in a three-column table that flattens to
  // "Bulletin ID Date Published Priority APSB26-146 September 7, 2026 1", so the value
  // trails the bulletin id rather than the "Date Published" header. Matching on the
  // header alone returned null for every bulletin in this layout.
  const published = (text.match(new RegExp(`${id}\\s+([A-Z][a-z]+ \\d{1,2},? \\d{4})`, 'i')) || [])[1]
    || (text.match(/(?:Date Published|Originally Published)[:\s]+([A-Z][a-z]+ \d{1,2},? \d{4})/) || [])[1]
    || (text.match(/Last updated on ([A-Z][a-z]{2} \d{1,2},? \d{4})/) || [])[1]
    || null;

  return {id, url, cves, versions, fixedVersions, hotfixUrl, severity, published};
};

/** The endpoint caps at 100 per page and now returns a full page, so the tail was
 *  being dropped. Results are published-descending, so this never hid a new advisory,
 *  but a state rebuild would have re-reported the truncated history as new. */
const fetchGhsa = async () => {
  const entries = [];
  let url = GHSA;

  for (let page = 1; url && page <= 20; page++) {
    const response = await fetchJson(url);
    if (!response || !Array.isArray(response.data)) break;
    entries.push(...response.data);
    url = response.next;
  }

  return entries
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
  const {ids: bulletinIds, urls: bulletinUrls} = await fetchBulletinIds();
  console.error(`  ${bulletinIds.length} bulletins listed`);

  const unseen = bulletinIds.filter(id => !previous[id]);
  // On a first run every bulletin is unseen; fetching 33 pages to establish a
  // baseline is wasteful when only the ids are needed to seed the state.
  const toFetch = baseline && !args.full ? [] : unseen.slice(0, Number(args.limit) || 25);
  if (toFetch.length) console.error(`fetching ${toFetch.length} new bulletin page(s)...`);

  const bulletins = [];
  for (const id of toFetch) {
    bulletins.push(await parseBulletin(id, bulletinUrls.get(id)));
  }

  console.error('fetching GHSA advisories...');
  const ghsa = await fetchGhsa();
  console.error(`  ${ghsa.length} advisories`);
  if (ghsa.length === 0) degrade('GHSA', 'no advisories returned');

  console.error('fetching Packagist advisories...');
  const packagist = await fetchPackagist();
  console.error(`  ${packagist.length} advisories`);
  if (packagist.length === 0) degrade('Packagist', 'no advisories returned');

  console.error('probing patch archives...');
  const archives = await fetchArchives(previous);
  console.error(`  ${archives.length} archive(s) published this month`);

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
      fixedVersions: bulletin.fixedVersions,
      hotfixUrl: bulletin.hotfixUrl,
      severity: bulletin.severity,
      url: bulletin.url,
      published: bulletin.published,
    });
    bulletin.cves.forEach(cve => cveToBulletin.set(cve, bulletin.id));
  }

  for (const archive of archives) {
    if (previous[archive.key]) continue;
    records.set(archive.key, {
      key: archive.key,
      kind: 'archive',
      sources: ['repo.magento.com'],
      cves: [],
      versions: [archive.stem.replace(/^(\d+)-(\d+)-(\d+)/, '$1.$2.$3')],
      severity: null,
      url: archive.url,
      published: null,
      entries: archive.entries,
      cePatch: archive.cePatch,
    });
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

  const report = {baseline, tracked: Object.keys(state).length, new: findings.length, findings, degraded};
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
  if (degraded.length) console.log(`${degraded.length} source(s) degraded: ${degraded.map(entry => entry.source).join(', ')}`);
  return degraded.length ? 2 : findings.length ? 1 : 0;
};

main().then(code => process.exit(code)).catch(exception => {
  console.error(exception);
  process.exit(3);
});
