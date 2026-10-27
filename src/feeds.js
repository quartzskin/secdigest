import { getValidators } from './db.js';

export const URLS = {
  kev: () => process.env.SECDIGEST_KEV_URL || 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  nvd: () => process.env.SECDIGEST_NVD_URL || 'https://services.nvd.nist.gov/rest/json/cves/2.0',
  osv: () => process.env.SECDIGEST_OSV_URL || 'https://api.osv.dev/v1/query',
};

const MAX_BODY = 64 * 1024 * 1024;

export class Pacer {
  constructor(intervals = {}, fallback = 1000) {
    this.intervals = intervals;
    this.fallback = fallback;
    this.last = new Map();
  }

  async wait(url) {
    const host = new URL(url).host;
    const gap = this.intervals[host] ?? this.fallback;
    const due = (this.last.get(host) ?? 0) + gap;
    const now = Date.now();
    if (due > now) await new Promise((r) => setTimeout(r, due - now));
    this.last.set(host, Date.now());
  }
}

export async function fetchCached(db, url, { method = 'GET', body, headers = {}, pacer, timeoutMs = 30000 } = {}) {
  if (!/^https?:\/\//i.test(url)) return { ok: false, error: 'only http(s) URLs are fetched' };
  const h = { 'user-agent': 'secdigest/0.1 (local, opt-in updater)', ...headers };
  const cacheable = method === 'GET';
  if (cacheable) {
    const v = getValidators(db, url);
    if (v?.etag) h['if-none-match'] = v.etag;
    if (v?.last_modified) h['if-modified-since'] = v.last_modified;
  }
  try {
    if (pacer) await pacer.wait(url);
    const res = await fetch(url, { method, body, headers: h, signal: AbortSignal.timeout(timeoutMs) });
    if (res.status === 304) return { ok: true, notModified: true };
    if (!res.ok) {
      const hint = res.status === 429 || res.status === 503 ? ' (rate limited or busy, try later)' : '';
      return { ok: false, error: `HTTP ${res.status}${hint}` };
    }
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length > MAX_BODY) return { ok: false, error: 'response too large' };
    return {
      ok: true,
      text: buf.toString('utf8'),
      validators: cacheable ? { etag: res.headers.get('etag'), lastModified: res.headers.get('last-modified') } : null,
    };
  } catch (err) {
    return { ok: false, error: err.name === 'TimeoutError' ? 'timed out' : String(err.cause?.code || err.message) };
  }
}

const str = (v) => (typeof v === 'string' && v.trim() ? v.trim() : null);
const isoDay = (v) => {
  const t = Date.parse(v);
  return Number.isNaN(t) ? null : new Date(t).toISOString();
};

function parseJson(text, what) {
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${what}: not valid JSON`);
  }
}

export function parseKev(text) {
  const data = parseJson(text, 'KEV');
  if (!data || !Array.isArray(data.vulnerabilities)) throw new Error('KEV: no vulnerabilities array');
  const out = [];
  for (const v of data.vulnerabilities) {
    const id = str(v?.cveID)?.toUpperCase();
    if (!id || !/^CVE-\d{4}-\d{3,}$/.test(id)) continue;
    out.push({
      id,
      source: 'kev',
      title: str(v.vulnerabilityName) || id,
      summary: [str(v.shortDescription), str(v.requiredAction) && `Required action: ${v.requiredAction.trim()}`].filter(Boolean).join(' '),
      vendor: str(v.vendorProject),
      product: str(v.product),
      kev: true,
      ransomware: /^known$/i.test(String(v.knownRansomwareCampaignUse || '').trim()),
      published: isoDay(v.dateAdded),
      url: `https://nvd.nist.gov/vuln/detail/${id}`,
    });
  }
  return out;
}

function splitCpe(s) {
  return s.split(/(?<!\\):/).map((p) => p.replace(/\\(.)/g, '$1'));
}

function collectCpes(configs) {
  const out = [];
  const walk = (node) => {
    for (const m of node?.cpeMatch ?? []) {
      if (m.vulnerable === false || typeof m.criteria !== 'string') continue;
      const p = splitCpe(m.criteria);
      if (p[0] !== 'cpe' || !['a', 'o'].includes(p[2]) || !p[3] || !p[4]) continue;
      out.push({
        vendor: p[3], product: p[4],
        version: p[5] && p[5] !== '*' && p[5] !== '-' ? p[5] : null,
        startIncl: m.versionStartIncluding ?? null, startExcl: m.versionStartExcluding ?? null,
        endIncl: m.versionEndIncluding ?? null, endExcl: m.versionEndExcluding ?? null,
      });
    }
    for (const c of node?.children ?? []) walk(c);
  };
  for (const cfg of Array.isArray(configs) ? configs : []) for (const n of cfg?.nodes ?? []) walk(n);
  return out.slice(0, 300);
}

export function severityFromScore(s) {
  if (typeof s !== 'number') return null;
  return s >= 9 ? 'critical' : s >= 7 ? 'high' : s >= 4 ? 'medium' : s > 0 ? 'low' : null;
}

function nvdScore(metrics) {
  for (const k of ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']) {
    const m = metrics?.[k]?.[0];
    const score = m?.cvssData?.baseScore;
    if (typeof score === 'number') return { cvss: score, severity: severityFromScore(score) };
  }
  return { cvss: null, severity: null };
}

export function parseNvd(text) {
  const data = parseJson(text, 'NVD');
  if (!data || !Array.isArray(data.vulnerabilities)) throw new Error('NVD: no vulnerabilities array');
  const out = [];
  for (const item of data.vulnerabilities) {
    const c = item?.cve;
    const id = str(c?.id)?.toUpperCase();
    if (!id || !/^CVE-\d{4}-\d{3,}$/.test(id)) continue;
    if (/^reject/i.test(String(c.vulnStatus || ''))) continue;
    const desc = (c.descriptions || []).find((d) => d.lang === 'en')?.value || '';
    const { cvss, severity } = nvdScore(c.metrics);
    out.push({
      id,
      source: 'nvd',
      title: `${id}: ${desc.split(/(?<=\.)\s/)[0].slice(0, 140) || 'no description'}`,
      summary: str(desc),
      cpes: collectCpes(c.configurations),
      severity, cvss,
      published: isoDay(c.published),
      url: `https://nvd.nist.gov/vuln/detail/${id}`,
    });
  }
  return out;
}

const OSV_SEVERITY = { critical: 'critical', high: 'high', moderate: 'medium', medium: 'medium', low: 'low' };

export function parseOsv(text, query) {
  const data = parseJson(text, 'OSV');
  if (!data || typeof data !== 'object') throw new Error('OSV: unexpected response');
  const out = [];
  for (const v of Array.isArray(data.vulns) ? data.vulns : []) {
    const id = str(v?.id);
    if (!id) continue;
    const sev = OSV_SEVERITY[String(v.database_specific?.severity || '').toLowerCase()] || null;
    out.push({
      id,
      source: 'osv',
      title: `${id}: ${str(v.summary) || 'no summary'}`.slice(0, 200),
      summary: str(v.details)?.slice(0, 1200) ?? str(v.summary),
      severity: sev,
      published: isoDay(v.published || v.modified),
      url: `https://osv.dev/vulnerability/${encodeURIComponent(id)}`,
      extra: { pkg: query.name, ecosystem: query.ecosystem, version: query.version, aliases: (v.aliases || []).filter((a) => typeof a === 'string') },
    });
  }
  return out;
}

const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };

function decode(s) {
  return s
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
      if (e[0] === '#') {
        const n = e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
        return n > 0 && n < 0x110000 ? String.fromCodePoint(n) : '';
      }
      return ENTITIES[e.toLowerCase()] ?? m;
    });
}

const plain = (s) => decode(decode(s).replace(/<[^>]*>/g, ' ')).replace(/\s+/g, ' ').trim();

function tagText(block, name) {
  const m = block.match(new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)</${name}>`, 'i'));
  return m ? plain(m[1]) : '';
}

export function parseRss(text) {
  const src = String(text);
  if (!/<(rss|feed|rdf:RDF)[\s>]/i.test(src)) throw new Error('RSS: not an RSS/Atom document');
  const blocks = src.match(/<(item|entry)[\s>][\s\S]*?<\/\1>/gi) || [];
  const out = [];
  for (const b of blocks.slice(0, 500)) {
    const title = tagText(b, 'title');
    if (!title) continue;
    const link = tagText(b, 'link') || b.match(/<link[^>]*href=["']([^"']+)["']/i)?.[1] || '';
    const guid = tagText(b, 'guid') || tagText(b, 'id') || link || title;
    out.push({
      guid, title, link: /^https?:\/\//i.test(link) ? link : '',
      summary: (tagText(b, 'description') || tagText(b, 'summary') || tagText(b, 'content')).slice(0, 1200),
      published: isoDay(tagText(b, 'pubDate') || tagText(b, 'updated') || tagText(b, 'published') || tagText(b, 'dc:date')),
    });
  }
  return out;
}
