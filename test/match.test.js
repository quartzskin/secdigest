import test from 'node:test';
import assert from 'node:assert/strict';
import { compareVersions, matchAdvisory, versionFits } from '../src/match.js';

const cpe = (o) => ({ vendor: 'acme', product: 'widget_studio', version: null, startIncl: null, startExcl: null, endIncl: null, endExcl: null, ...o });
const adv = (o) => ({ id: 'X', sources: ['nvd'], cpes: [], extra: {}, title: '', summary: '', ...o });
const sw = (name, version, publisher = '', ecosystem = '') => ({ name, version, publisher, ecosystem });

test('version comparison', () => {
  assert.equal(compareVersions('4.2.0', '4.2.1'), -1);
  assert.equal(compareVersions('4.10', '4.9'), 1);
  assert.equal(compareVersions('2.0', '2.0.0'), 0);
  assert.equal(compareVersions('abc', '1'), null);
  assert.equal(versionFits('', cpe({ endExcl: '2' })), null);
  assert.equal(versionFits('1.5', cpe({ startIncl: '1.0', endExcl: '2.0' })), true);
  assert.equal(versionFits('2.0', cpe({ startIncl: '1.0', endExcl: '2.0' })), false);
});

test('CPE match in range: high confidence with reason and version note', () => {
  const m = matchAdvisory(adv({ cpes: [cpe({ endExcl: '4.2.1' })] }), sw('Acme Widget Studio', '4.1.0', 'Acme Corp'));
  assert.equal(m.confidence, 'high');
  assert.match(m.reason, /product "widget studio" appears in "Acme Widget Studio"/);
  assert.match(m.note, /^may affect: version 4\.1\.0 falls in the listed range \(before 4\.2\.1\)/);
});

test('CPE match with fixed version installed: dropped', () => {
  assert.equal(matchAdvisory(adv({ cpes: [cpe({ endExcl: '4.2.1' })] }), sw('Acme Widget Studio', '4.2.1', 'Acme Corp')), null);
});

test('merged KEV+NVD: out-of-range CPE suppresses the name-only KEV match', () => {
  const a = adv({ sources: ['kev', 'nvd'], vendor: 'Acme', product: 'Widget Studio', kev: true, cpes: [cpe({ endExcl: '4.2.1' })] });
  assert.equal(matchAdvisory(a, sw('Acme Widget Studio', '9.0', 'Acme Corp')), null);
});

test('unknown version lowers confidence and says so', () => {
  const m = matchAdvisory(adv({ cpes: [cpe({ endExcl: '4.2.1' })] }), sw('Acme Widget Studio', '', 'Acme Corp'));
  assert.equal(m.confidence, 'medium');
  assert.match(m.note, /no version recorded/);
});

test('KEV vendor/product: vendor+product high, product only medium, vendor only none', () => {
  const kev = adv({ sources: ['kev'], vendor: 'Acme', product: 'Widget Studio', kev: true });
  assert.equal(matchAdvisory(kev, sw('Widget Studio', '1', 'Acme Corp')).confidence, 'high');
  assert.equal(matchAdvisory(kev, sw('Widget Studio', '1', 'Someone Else')).confidence, 'medium');
  assert.equal(matchAdvisory(kev, sw('Acme Calculator', '1', 'Acme Corp')), null);
  assert.match(matchAdvisory(kev, sw('Widget Studio', '1.2', 'Acme')).note, /lists no version ranges; check version 1\.2/);
});

test('short single-token products stay low; compact names match', () => {
  const git = adv({ sources: ['kev'], vendor: 'Other', product: 'git' });
  assert.equal(matchAdvisory(git, sw('Git', '2', 'The Git Project')).confidence, 'low');
  const z = adv({ sources: ['kev'], vendor: '7-zip', product: '7-zip' });
  assert.equal(matchAdvisory(z, sw('7zip 23.01 (x64)', '23.01', 'Igor Pavlov')).confidence, 'high');
});

test('near-miss spelling is low confidence, not exact', () => {
  const a = adv({ sources: ['kev'], vendor: 'Acme', product: 'Widgetstudio' });
  const m = matchAdvisory(a, sw('Acme Widgetstudoi', '1', 'Acme'));
  assert.equal(m, null);
  const b = adv({ sources: ['kev'], vendor: 'Acme', product: 'Archiver' });
  assert.equal(matchAdvisory(b, sw('Acme Archivor', '1', 'Acme')).confidence, 'low');
});

test('OSV matches only the queried package and version', () => {
  const a = adv({ sources: ['osv'], extra: { pkg: 'leftpadder', ecosystem: 'npm', version: '1.0.0' } });
  assert.equal(matchAdvisory(a, sw('leftpadder', '1.0.0', '', 'npm')).confidence, 'high');
  assert.equal(matchAdvisory(a, sw('leftpadder', '1.0.1', '', 'npm')), null);
  assert.equal(matchAdvisory(a, sw('leftpadder', '1.0.0', '', 'PyPI')), null);
});

test('RSS items match on name words', () => {
  const a = adv({ sources: ['rss'], title: 'Fabrikam Archiver 1.4 fixes a heap overflow', summary: '', vendor: 'Fabrikam' });
  assert.equal(matchAdvisory(a, sw('Fabrikam Archiver', '1.3')).confidence, 'medium');
  assert.equal(matchAdvisory(a, sw('Unrelated Tool', '1.3')), null);
  const b = adv({ sources: ['rss'], title: 'Archiver news', vendor: 'Fabrikam' });
  assert.equal(matchAdvisory(b, sw('Fabrikam Archiver Pro', '1', 'Fabrikam Inc')).confidence, 'low');
});
