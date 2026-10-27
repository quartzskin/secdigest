import { createHash } from 'node:crypto';
import { listFeeds, listRules, listSoftware, saveValidators, upsertAdvisory } from './db.js';
import { Pacer, URLS, fetchCached, parseKev, parseNvd, parseOsv, parseRss } from './feeds.js';
import { isActive } from './inventory.js';

export const SOURCES = ['kev', 'nvd', 'osv', 'rss'];

function nvdUrl(days, page, startIndex) {
  const end = new Date();
  const start = new Date(end.getTime() - days * 86400000);
  const fmt = (d) => d.toISOString().replace('Z', '');
  const q = new URLSearchParams({
    lastModStartDate: fmt(start), lastModEndDate: fmt(end),
    resultsPerPage: String(page), startIndex: String(startIndex),
  });
  return `${URLS.nvd()}?${q}`;
}

function store(db, list) {
  db.exec('BEGIN');
  try {
    for (const a of list) upsertAdvisory(db, a);
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

async function updateKev(db, ctx) {
  const url = URLS.kev();
  if (ctx.dryRun) return { detail: `would GET ${url}` };
  const r = await fetchCached(db, url, ctx);
  if (!r.ok) return { error: r.error };
  if (r.notModified) return { detail: 'not modified' };
  const list = parseKev(r.text);
  store(db, list);
  saveValidators(db, url, r.validators);
  return { detail: `${list.length} entries` };
}

async function updateNvd(db, ctx) {
  const days = Math.min(Math.max(ctx.days, 1), 119);
  if (ctx.dryRun) return { detail: `would GET ${nvdUrl(days, 500, 0)}` };
  const MAX_PAGES = 10;
  let total = 0;
  let start = 0;
  for (let page = 0; page < MAX_PAGES; page++) {
    const url = nvdUrl(days, 500, start);
    const r = await fetchCached(db, url, { ...ctx, timeoutMs: 120000, headers: process.env.NVD_API_KEY ? { apikey: process.env.NVD_API_KEY } : {} });
    if (!r.ok) return { error: r.error, detail: total ? `${total} entries before the error` : undefined };
    if (r.notModified) break;
    const list = parseNvd(r.text);
    store(db, list);
    total += list.length;
    const meta = JSON.parse(r.text);
    start += Number(meta.resultsPerPage) || 0;
    if (!meta.resultsPerPage || start >= Number(meta.totalResults)) break;
  }
  return { detail: `${total} CVEs modified in the last ${days} day(s)` };
}

async function updateOsv(db, ctx) {
  const rules = listRules(db);
  const targets = listSoftware(db).filter((s) => s.ecosystem && s.version && isActive(s, rules));
  if (!targets.length) return { detail: 'no inventory entries with an ecosystem set, skipped' };
  if (ctx.dryRun) return { detail: `would POST ${targets.length} package queries to ${URLS.osv()}` };
  let total = 0;
  const errors = [];
  for (const s of targets) {
    const q = { name: s.name, ecosystem: s.ecosystem, version: s.version };
    const body = JSON.stringify({ version: q.version, package: { name: q.name, ecosystem: q.ecosystem } });
    const r = await fetchCached(db, URLS.osv(), { ...ctx, method: 'POST', body, headers: { 'content-type': 'application/json' } });
    if (!r.ok) { errors.push(`${s.name}: ${r.error}`); continue; }
    try {
      const list = parseOsv(r.text, q);
      store(db, list);
      total += list.length;
    } catch (err) {
      errors.push(`${s.name}: ${err.message}`);
    }
  }
  return { detail: `${total} advisories for ${targets.length} package(s)`, error: errors.length ? errors.join('; ') : undefined };
}

async function updateRss(db, ctx) {
  const feeds = listFeeds(db);
  if (!feeds.length) return { detail: 'no RSS feeds configured, skipped' };
  if (ctx.dryRun) return { detail: feeds.map((f) => `would GET ${f.url}`).join('; ') };
  let total = 0;
  const errors = [];
  for (const f of feeds) {
    const r = await fetchCached(db, f.url, ctx);
    if (!r.ok) { errors.push(`${f.url}: ${r.error}`); continue; }
    if (r.notModified) continue;
    try {
      const items = parseRss(r.text);
      store(db, items.map((i) => ({
        id: `rss:${createHash('sha1').update(f.url + i.guid).digest('hex').slice(0, 16)}`,
        source: 'rss', title: i.title, summary: i.summary, url: i.link || null,
        published: i.published, vendor: f.vendor || null, extra: { feed: f.url },
      })));
      saveValidators(db, f.url, r.validators);
      total += items.length;
    } catch (err) {
      errors.push(`${f.url}: ${err.message}`);
    }
  }
  return { detail: `${total} items from ${feeds.length} feed(s)`, error: errors.length ? errors.join('; ') : undefined };
}

const RUNNERS = { kev: updateKev, nvd: updateNvd, osv: updateOsv, rss: updateRss };

// delayMs, when set, replaces every per-host gap (tests use 0).
export async function runUpdate(db, { only = SOURCES, dryRun = false, days = 2, delayMs } = {}) {
  const hasKey = !!process.env.NVD_API_KEY;
  const nvdHost = new URL(URLS.nvd()).host;
  const pacer = new Pacer(delayMs == null ? { [nvdHost]: hasKey ? 700 : 6500 } : {}, delayMs ?? 1000);
  const ctx = { pacer, dryRun, days };
  const results = [];
  for (const name of SOURCES.filter((s) => only.includes(s))) {
    try {
      results.push({ name, ...(await RUNNERS[name](db, ctx)) });
    } catch (err) {
      results.push({ name, error: err.message });
    }
  }
  return results;
}
