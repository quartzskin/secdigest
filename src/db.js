import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS software (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '',
  publisher TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL,
  ecosystem TEXT NOT NULL DEFAULT '',
  UNIQUE (name, version, source)
);
CREATE TABLE IF NOT EXISTS rules (
  kind TEXT NOT NULL CHECK (kind IN ('allow', 'ignore')),
  pattern TEXT NOT NULL,
  PRIMARY KEY (kind, pattern)
);
CREATE TABLE IF NOT EXISTS rss_feeds (
  url TEXT PRIMARY KEY,
  vendor TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS http_cache (
  url TEXT PRIMARY KEY,
  etag TEXT,
  last_modified TEXT,
  fetched_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS advisories (
  id TEXT PRIMARY KEY,
  sources TEXT NOT NULL,
  title TEXT NOT NULL,
  summary TEXT,
  vendor TEXT,
  product TEXT,
  cpes TEXT,
  severity TEXT,
  cvss REAL,
  kev INTEGER NOT NULL DEFAULT 0,
  ransomware INTEGER NOT NULL DEFAULT 0,
  published TEXT,
  url TEXT,
  extra TEXT,
  seen TEXT NOT NULL
);
`;

export function defaultDbPath() {
  if (process.env.SECDIGEST_DB) return process.env.SECDIGEST_DB;
  const base = process.env.LOCALAPPDATA || join(homedir(), '.local', 'share');
  return join(base, 'secdigest', 'secdigest.db');
}

export function openDb(path = defaultDbPath()) {
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec(SCHEMA);
  return db;
}

export function listSoftware(db) {
  return db.prepare('SELECT * FROM software ORDER BY name COLLATE NOCASE, version').all();
}

export function listRules(db) {
  return db.prepare('SELECT kind, pattern FROM rules ORDER BY kind, pattern').all();
}

export function addRule(db, kind, pattern) {
  db.prepare('INSERT OR IGNORE INTO rules (kind, pattern) VALUES (?, ?)').run(kind, pattern);
}

export function removeRule(db, pattern) {
  return Number(db.prepare('DELETE FROM rules WHERE pattern = ? COLLATE NOCASE').run(pattern).changes);
}

export function addManual(db, { name, version = '', publisher = '', ecosystem = '' }) {
  db.prepare(
    "INSERT OR REPLACE INTO software (name, version, publisher, source, ecosystem) VALUES (?, ?, ?, 'manual', ?)"
  ).run(name, version, publisher, ecosystem);
}

export function removeManual(db, name) {
  return Number(db.prepare("DELETE FROM software WHERE source = 'manual' AND name = ? COLLATE NOCASE").run(name).changes);
}

export function replaceScanned(db, entries) {
  db.exec('BEGIN');
  try {
    db.exec("DELETE FROM software WHERE source != 'manual'");
    const ins = db.prepare('INSERT OR IGNORE INTO software (name, version, publisher, source) VALUES (?, ?, ?, ?)');
    for (const e of entries) ins.run(e.name, e.version || '', e.publisher || '', e.source);
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

export function addFeed(db, url, vendor = '') {
  db.prepare('INSERT OR REPLACE INTO rss_feeds (url, vendor) VALUES (?, ?)').run(url, vendor);
}

export function removeFeed(db, url) {
  return Number(db.prepare('DELETE FROM rss_feeds WHERE url = ?').run(url).changes);
}

export function listFeeds(db) {
  return db.prepare('SELECT url, vendor FROM rss_feeds ORDER BY url').all();
}

export function getValidators(db, url) {
  return db.prepare('SELECT etag, last_modified FROM http_cache WHERE url = ?').get(url);
}

export function saveValidators(db, url, v) {
  db.prepare('INSERT OR REPLACE INTO http_cache (url, etag, last_modified, fetched_at) VALUES (?, ?, ?, ?)')
    .run(url, v.etag || null, v.lastModified || null, new Date().toISOString());
}

const json = (v) => (v == null ? null : JSON.stringify(v));
const later = (a, b) => (!a ? b : !b ? a : a > b ? a : b);

export function upsertAdvisory(db, a) {
  const old = db.prepare('SELECT * FROM advisories WHERE id = ?').get(a.id);
  const now = new Date().toISOString();
  if (!old) {
    db.prepare(`INSERT INTO advisories
      (id, sources, title, summary, vendor, product, cpes, severity, cvss, kev, ransomware, published, url, extra, seen)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      a.id, a.source, a.title, a.summary ?? null, a.vendor ?? null, a.product ?? null,
      json(a.cpes?.length ? a.cpes : null), a.severity ?? null, a.cvss ?? null,
      a.kev ? 1 : 0, a.ransomware ? 1 : 0, a.published ?? null, a.url ?? null, json(a.extra), now
    );
    return;
  }
  const sources = [...new Set([...old.sources.split(','), a.source])].join(',');
  const extra = { ...(old.extra ? JSON.parse(old.extra) : {}), ...(a.extra || {}) };
  db.prepare(`UPDATE advisories SET sources = ?, title = ?, summary = ?, vendor = ?, product = ?, cpes = ?,
      severity = ?, cvss = ?, kev = ?, ransomware = ?, published = ?, url = ?, extra = ? WHERE id = ?`).run(
    sources, a.title || old.title, a.summary ?? old.summary, a.vendor ?? old.vendor, a.product ?? old.product,
    a.cpes?.length ? json(a.cpes) : old.cpes, a.severity ?? old.severity, a.cvss ?? old.cvss,
    a.kev || old.kev ? 1 : 0, a.ransomware || old.ransomware ? 1 : 0,
    later(old.published, a.published), a.url ?? old.url, json(extra), a.id
  );
}

export function listAdvisories(db) {
  return db.prepare('SELECT * FROM advisories').all().map((r) => ({
    ...r,
    sources: r.sources.split(','),
    cpes: r.cpes ? JSON.parse(r.cpes) : [],
    extra: r.extra ? JSON.parse(r.extra) : {},
    kev: !!r.kev,
    ransomware: !!r.ransomware,
  }));
}
