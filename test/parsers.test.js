import test from 'node:test';
import assert from 'node:assert/strict';
import { parseKev, parseNvd, parseOsv, parseRss } from '../src/feeds.js';
import { parseRegistryJson, parseWingetList, mergeScans, isActive } from '../src/inventory.js';
import { fixture } from '../testkit/helpers.js';

test('KEV: parses entries, skips bad ids', () => {
  const list = parseKev(fixture('kev.json'));
  assert.deepEqual(list.map((a) => a.id), ['CVE-2025-1001', 'CVE-2025-1002']);
  assert.equal(list[0].kev, true);
  assert.equal(list[0].ransomware, true);
  assert.equal(list[1].ransomware, false);
  assert.equal(list[0].published, '2025-01-02T00:00:00.000Z');
});

test('KEV: malformed input throws a plain error', () => {
  assert.throws(() => parseKev('{not json'), /not valid JSON/);
  assert.throws(() => parseKev('{"vulnerabilities": 5}'), /no vulnerabilities/);
  assert.throws(() => parseKev('null'), /no vulnerabilities/);
  assert.deepEqual(parseKev('{"vulnerabilities":[null,1,"x",{}]}'), []);
});

test('NVD: CPE ranges, score fallback, rejected CVEs dropped', () => {
  const list = parseNvd(fixture('nvd.json'));
  assert.deepEqual(list.map((a) => a.id), ['CVE-2025-1001', 'CVE-2025-2002']);
  assert.equal(list[0].severity, 'critical');
  assert.equal(list[0].cpes[0].endExcl, '4.2.1');
  assert.equal(list[0].cpes[0].product, 'widget_studio');
  assert.equal(list[1].severity, 'medium');
  assert.match(list[0].title, /^CVE-2025-1001: Path traversal in Acme Widget Studio before 4\.2\.1 allows file reads\.$/);
});

test('NVD: malformed input and odd cpe strings', () => {
  assert.throws(() => parseNvd('<html>'), /not valid JSON/);
  assert.throws(() => parseNvd('{}'), /no vulnerabilities/);
  const odd = JSON.stringify({ vulnerabilities: [{ cve: { id: 'CVE-2025-9999', configurations: [{ nodes: [{ cpeMatch: [{ criteria: 'garbage' }, { criteria: 'cpe:2.3:h:x:y' }, { criteria: 'cpe:2.3:a:ven\\:dor:prod:1.2:*' }] }, null] }, null] } }, null] });
  const [a] = parseNvd(odd);
  assert.equal(a.cpes.length, 1);
  assert.equal(a.cpes[0].vendor, 'ven:dor');
  assert.equal(a.cpes[0].version, '1.2');
});

test('OSV: maps severity, skips entries without id', () => {
  const list = parseOsv(fixture('osv.json'), { name: 'leftpadder', ecosystem: 'npm', version: '1.0.0' });
  assert.equal(list.length, 1);
  assert.equal(list[0].severity, 'medium');
  assert.equal(list[0].extra.pkg, 'leftpadder');
  assert.deepEqual(parseOsv('{}', {}), []);
  assert.throws(() => parseOsv('oops', {}), /not valid JSON/);
});

test('RSS: decodes CDATA/entities, drops non-http links, tolerates bad dates', () => {
  const items = parseRss(fixture('feed.rss'));
  assert.equal(items.length, 2);
  assert.equal(items[0].summary, 'Update Archiver & check your install.');
  assert.equal(items[0].published, '2025-01-04T09:00:00.000Z');
  assert.equal(items[1].link, '');
  assert.equal(items[1].published, null);
});

test('Atom entries parse', () => {
  const [e] = parseRss(fixture('atom.xml'));
  assert.equal(e.link, 'https://example.test/ws');
  assert.equal(e.published, '2025-01-06T00:00:00.000Z');
});

test('RSS: malformed documents', () => {
  assert.throws(() => parseRss('<html><body>login</body></html>'), /not an RSS/);
  assert.throws(() => parseRss(''), /not an RSS/);
  assert.deepEqual(parseRss('<rss><channel><item><title>cut off'), []);
  assert.deepEqual(parseRss('<rss><item><link>x</link></item></rss>'), []);
});

test('registry JSON: single object, BOM, junk rows', () => {
  const rows = parseRegistryJson(fixture('registry.json'));
  assert.deepEqual(rows, [{ name: 'Acme Widget Studio', version: '4.1.0', publisher: 'Acme Corp', source: 'registry' }]);
  assert.equal(parseRegistryJson('{"name":"Solo","version":"1"}').length, 1);
  assert.deepEqual(parseRegistryJson('garbage'), []);
  assert.deepEqual(parseRegistryJson(''), []);
});

test('winget list columns', () => {
  const rows = parseWingetList(fixture('winget.txt'));
  assert.deepEqual(rows.map((r) => [r.name, r.version]), [['Git', '2.45.1'], ['7-Zip 23.01 (x64)', '23.01'], ['Widget Studio', '4.1.0']]);
  assert.deepEqual(parseWingetList('No installed package found'), []);
  assert.deepEqual(parseWingetList(''), []);
});

test('mergeScans keeps the first of duplicate name+version', () => {
  const m = mergeScans([{ name: 'Git', version: '1', source: 'registry' }], [{ name: 'git', version: '1', source: 'winget' }, { name: 'Git', version: '2', source: 'winget' }]);
  assert.deepEqual(m.map((e) => e.source), ['registry', 'winget']);
});

test('allow/ignore rules', () => {
  const sw = { name: 'Acme Widget Studio', publisher: 'Acme Corp' };
  assert.equal(isActive(sw, []), true);
  assert.equal(isActive(sw, [{ kind: 'ignore', pattern: 'widget*' }]), false);
  assert.equal(isActive(sw, [{ kind: 'ignore', pattern: 'nothing' }]), true);
  assert.equal(isActive(sw, [{ kind: 'allow', pattern: 'git' }]), false);
  assert.equal(isActive(sw, [{ kind: 'allow', pattern: 'acme' }]), true);
  assert.equal(isActive(sw, [{ kind: 'allow', pattern: 'acme' }, { kind: 'ignore', pattern: 'widget' }]), false);
});
