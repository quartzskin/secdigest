import test from 'node:test';
import assert from 'node:assert/strict';
import { addFeed, addManual, addRule, listAdvisories, openDb, replaceScanned } from '../src/db.js';
import { runUpdate } from '../src/update.js';
import { buildDigest } from '../src/digest.js';
import { renderHtml, renderMarkdown, renderText } from '../src/render.js';
import { main } from '../src/cli.js';
import { fakeServer, fixture } from '../testkit/helpers.js';

async function withFeeds(routes, fn) {
  const srv = await fakeServer(routes);
  const saved = { ...process.env };
  process.env.SECDIGEST_KEV_URL = `${srv.base}/kev.json`;
  process.env.SECDIGEST_NVD_URL = `${srv.base}/nvd`;
  process.env.SECDIGEST_OSV_URL = `${srv.base}/osv`;
  try {
    return await fn(srv);
  } finally {
    for (const k of ['SECDIGEST_KEV_URL', 'SECDIGEST_NVD_URL', 'SECDIGEST_OSV_URL']) {
      if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k];
    }
    await srv.close();
  }
}

const GOOD = () => ({
  '/kev.json': { body: fixture('kev.json'), etag: '"kev1"' },
  '/nvd': { body: fixture('nvd.json') },
  '/osv': { body: fixture('osv.json') },
  '/feed.rss': { body: fixture('feed.rss'), type: 'application/rss+xml' },
});

function seeded() {
  const db = openDb(':memory:');
  replaceScanned(db, [
    { name: 'Acme Widget Studio', version: '4.1.0', publisher: 'Acme Corp', source: 'registry' },
    { name: 'Fabrikam Archiver', version: '1.3', publisher: 'Fabrikam', source: 'registry' },
    { name: 'Contoso Office', version: '16.0', publisher: 'Contoso', source: 'registry' },
    { name: 'Unrelated Editor', version: '2.0', publisher: 'Nobody', source: 'registry' },
  ]);
  addManual(db, { name: 'leftpadder', version: '1.0.0', ecosystem: 'npm' });
  return db;
}

test('update fetches all feeds, stores advisories, second run uses 304', async () => {
  await withFeeds(GOOD(), async (srv) => {
    const db = seeded();
    addFeed(db, `${srv.base}/feed.rss`, 'Fabrikam');
    const r1 = await runUpdate(db, { delayMs: 0 });
    assert.deepEqual(r1.map((r) => [r.name, !r.error]), [['kev', true], ['nvd', true], ['osv', true], ['rss', true]]);
    const ids = listAdvisories(db).map((a) => a.id);
    assert.ok(ids.includes('CVE-2025-1001'));
    assert.ok(ids.includes('GHSA-xxxx-yyyy-zzzz'));
    assert.equal(listAdvisories(db).find((a) => a.id === 'CVE-2025-1001').sources.sort().join(), 'kev,nvd');
    const r2 = await runUpdate(db, { only: ['kev'], delayMs: 0 });
    assert.equal(r2[0].detail, 'not modified');
    const kevHits = srv.hits.filter((h) => h.path === '/kev.json');
    assert.equal(kevHits[1].headers['if-none-match'], '"kev1"');
    assert.equal(kevHits[0].headers['if-none-match'], undefined);
    assert.match(kevHits[0].headers['user-agent'], /^secdigest\//);
  });
});

test('dry run sends nothing', async () => {
  await withFeeds(GOOD(), async (srv) => {
    const db = seeded();
    const r = await runUpdate(db, { dryRun: true, delayMs: 0 });
    assert.equal(srv.hits.length, 0);
    assert.match(r[0].detail, /would GET/);
    assert.equal(listAdvisories(db).length, 0);
  });
});

test('malformed and failing feeds are reported, not thrown', async () => {
  const routes = {
    '/kev.json': { body: '{"vulnerabilities": [' },
    '/nvd': { status: 503, body: 'busy' },
    '/osv': { body: '<<<' },
    '/bad.rss': { body: '<html>captive portal</html>', type: 'text/html' },
    '/ok.rss': { body: fixture('atom.xml') },
  };
  await withFeeds(routes, async (srv) => {
    const db = seeded();
    addFeed(db, `${srv.base}/bad.rss`);
    addFeed(db, `${srv.base}/ok.rss`);
    addFeed(db, `${srv.base}/missing.rss`);
    const r = await runUpdate(db, { delayMs: 0 });
    const by = Object.fromEntries(r.map((x) => [x.name, x]));
    assert.match(by.kev.error, /not valid JSON/);
    assert.match(by.nvd.error, /HTTP 503.*rate limited/);
    assert.match(by.osv.error, /not valid JSON/);
    assert.match(by.rss.error, /not an RSS/);
    assert.match(by.rss.error, /HTTP 404/);
    assert.match(by.rss.detail, /^1 items/);
    assert.equal(listAdvisories(db).filter((a) => a.id.startsWith('rss:')).length, 1);
  });
});

test('unreachable host gives an error string', async () => {
  const saved = process.env.SECDIGEST_KEV_URL;
  process.env.SECDIGEST_KEV_URL = 'http://127.0.0.1:1/kev.json';
  try {
    const [r] = await runUpdate(openDb(':memory:'), { only: ['kev'], delayMs: 0 });
    assert.ok(r.error);
  } finally {
    if (saved === undefined) delete process.env.SECDIGEST_KEV_URL; else process.env.SECDIGEST_KEV_URL = saved;
  }
});

test('digest ranks KEV first, explains matches, honours ignore rules', async () => {
  await withFeeds(GOOD(), async (srv) => {
    const db = seeded();
    addFeed(db, `${srv.base}/feed.rss`, 'Fabrikam');
    await runUpdate(db, { delayMs: 0 });
    const now = new Date('2025-01-10T00:00:00Z');
    const d = buildDigest(db, { days: 30, now });
    assert.equal(d.items[0].id, 'CVE-2025-1001');
    assert.equal(d.lead.id, 'CVE-2025-1001');
    assert.equal(d.items[0].kev, true);
    assert.equal(d.items[0].matches[0].software.name, 'Acme Widget Studio');
    assert.match(d.items[0].matches[0].note, /^may affect/);
    const ids = d.items.map((i) => i.id);
    assert.ok(ids.includes('CVE-2025-2002'));
    assert.ok(ids.includes('GHSA-xxxx-yyyy-zzzz'));
    assert.ok(ids.includes('CVE-2025-1002'));
    assert.equal(d.counts.kev, 2);
    assert.equal(d.weather.label, 'Stormy');
    assert.ok(!d.items.some((i) => i.matches.some((m) => m.software.name === 'Unrelated Editor')));

    const narrow = buildDigest(db, { days: 1, now });
    assert.equal(narrow.items.length, 0);
    assert.equal(narrow.weather.label, 'Clear');

    addRule(db, 'ignore', 'acme*');
    const after = buildDigest(db, { days: 30, now });
    assert.ok(!after.items.some((i) => i.id === 'CVE-2025-1001'));
    const highOnly = buildDigest(db, { days: 30, now, minConfidence: 'high' });
    assert.ok(highOnly.items.every((i) => i.confidence === 'high'));
  });
});

test('renderers produce text, markdown and escaped html', () => {
  const db = seeded();
  db.prepare("INSERT INTO advisories (id, sources, title, summary, vendor, product, kev, published, seen) VALUES ('CVE-2025-7777', 'kev', '<script>alert(1)</script> Widget', 's', 'Acme', 'Widget Studio', 1, '2025-01-09T00:00:00Z', '2025-01-09T00:00:00Z')").run();
  const d = buildDigest(db, { now: new Date('2025-01-10T00:00:00Z') });
  assert.match(renderText(d), /\[KEV, high confidence\]/);
  assert.match(renderMarkdown(d), /^# secdigest 2025-01-10/);
  const html = renderHtml(d);
  assert.ok(!html.includes('<script>alert'));
  assert.match(html, /&lt;script&gt;/);
  assert.match(renderText(buildDigest(openDb(':memory:'))), /Nothing matched/);
});

test('cli: inventory, feeds, digest, bad input', async () => {
  const lines = [];
  const out = (s) => lines.push(s);
  const dbf = ':memory:';
  assert.equal(await main(['inventory', 'add', 'Acme Widget Studio', '4.1.0', '--db', dbf], { out }), 0);
  assert.equal(await main(['inventory', 'add', '--db', dbf], { out }), 2);
  assert.equal(await main(['feeds', 'add', 'ftp://nope', '--db', dbf], { out }), 2);
  assert.equal(await main(['update', '--only', 'bogus', '--db', dbf], { out }), 2);
  assert.equal(await main(['digest', '--format', 'pdf', '--db', dbf], { out }), 2);
  assert.equal(await main(['frobnicate'], { out }), 2);
  assert.equal(await main([], { out }), 2);
  assert.equal(await main(['digest', '--db', dbf], { out }), 0);
  assert.equal(await main(['ui', '--port', '99999', '--db', dbf], { out }), 2);
  assert.match(lines.join('\n'), /usage: inventory add/);
});
