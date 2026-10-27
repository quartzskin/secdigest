const STOP = new Set([
  'inc', 'corp', 'corporation', 'ltd', 'llc', 'co', 'the', 'software', 'x64', 'x86', 'amd64',
  'bit', 'version', 'edition', 'for', 'and', 'of', 'project', 'foundation', 'team',
]);

export const CONF_RANK = { low: 1, medium: 2, high: 3 };
const RANK_CONF = ['', 'low', 'medium', 'high'];

export function tokens(s) {
  return String(s || '').toLowerCase().split(/[^a-z0-9]+/).filter((t) => t && !STOP.has(t));
}

const compact = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]/g, '');

function editDistanceAtMostOne(a, b) {
  if (Math.abs(a.length - b.length) > 1) return false;
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  if (i === a.length && i === b.length) return true;
  if (a.length === b.length) return a.slice(i + 1) === b.slice(i + 1);
  return a.length > b.length ? a.slice(i + 1) === b.slice(i) : a.slice(i) === b.slice(i + 1);
}

export function versionParts(v) {
  const nums = String(v || '').match(/\d+/g);
  return nums ? nums.slice(0, 6).map(Number) : null;
}

export function compareVersions(a, b) {
  const pa = versionParts(a);
  const pb = versionParts(b);
  if (!pa || !pb) return null;
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}

// true / false when the CPE range decides it, null when the version is unusable.
export function versionFits(version, c) {
  if (!versionParts(version)) return null;
  const checks = [
    [c.version, (r) => r === 0],
    [c.startIncl, (r) => r >= 0],
    [c.startExcl, (r) => r > 0],
    [c.endIncl, (r) => r <= 0],
    [c.endExcl, (r) => r < 0],
  ];
  for (const [bound, ok] of checks) {
    if (!bound) continue;
    const r = compareVersions(version, bound);
    if (r === null) return null;
    if (!ok(r)) return false;
  }
  return true;
}

function describeRange(c) {
  if (c.version) return `exactly ${c.version}`;
  const parts = [];
  if (c.startIncl) parts.push(`from ${c.startIncl}`);
  if (c.startExcl) parts.push(`after ${c.startExcl}`);
  if (c.endIncl) parts.push(`up to ${c.endIncl}`);
  if (c.endExcl) parts.push(`before ${c.endExcl}`);
  return parts.join(' ') || 'all versions';
}

function productMatch(product, nameToks, nameCompact) {
  const pt = tokens(product);
  if (!pt.length) return null;
  const set = new Set(nameToks);
  if (pt.every((t) => set.has(t))) return 'exact';
  const pc = compact(product);
  if (pc.length >= 4 && nameCompact.includes(pc)) return 'exact';
  const near = pt.map((t) => (set.has(t) ? 'same' : t.length >= 6 && nameToks.some((n) => n[0] === t[0] && editDistanceAtMostOne(t, n)) ? 'near' : null));
  if (near.every(Boolean) && near.includes('near')) return 'fuzzy';
  return null;
}

function vendorMatch(vendor, sw) {
  const vt = tokens(vendor);
  if (!vt.length) return false;
  const hay = new Set([...tokens(sw.name), ...tokens(sw.publisher)]);
  if (vt.every((t) => hay.has(t))) return true;
  const vc = compact(vendor);
  return vc.length >= 3 && compact(`${sw.publisher} ${sw.name}`).includes(vc);
}

// Platform words match half the inventory ("Windows SDK AddOn"), so they never rate above low.
const GENERIC = new Set(['windows', 'linux', 'android', 'ios', 'macos', 'mac', 'server', 'client', 'desktop', 'system', 'web', 'browser', 'office']);

function weakProduct(product) {
  const t = tokens(product);
  return (t.length === 1 && t[0].length < 4) || t.every((x) => GENERIC.has(x));
}

function nameDecision(vendor, product, sw) {
  const nameToks = tokens(sw.name);
  const pm = productMatch(product, nameToks, compact(sw.name));
  if (!pm) return null;
  const vm = vendorMatch(vendor, sw);
  let conf;
  if (pm === 'fuzzy') conf = 'low';
  else if (weakProduct(product)) conf = 'low';
  else conf = vm ? 'high' : 'medium';
  const how = pm === 'fuzzy' ? 'is spelled almost like' : 'appears in';
  const reason = `product "${product}" ${how} "${sw.name}"` +
    (vendor ? (vm ? `, and vendor "${vendor}" matches ${sw.publisher ? `publisher "${sw.publisher}"` : 'the name'}` : `; vendor "${vendor}" did not match`) : '');
  return { conf, reason };
}

function demote(conf) {
  return RANK_CONF[Math.max(1, CONF_RANK[conf] - 1)];
}

function matchCpes(adv, sw) {
  let best = null;
  let fits = false;
  let excluded = false;
  const ranges = [];
  for (const c of adv.cpes) {
    const d = nameDecision(c.vendor.replace(/_/g, ' '), c.product.replace(/_/g, ' '), sw);
    if (!d) continue;
    const fit = versionFits(sw.version, c);
    if (fit === false) { excluded = true; continue; }
    if (!best || CONF_RANK[d.conf] > CONF_RANK[best.conf]) best = d;
    if (fit === true) fits = true;
    if (!ranges.includes(describeRange(c))) ranges.push(describeRange(c));
  }
  if (!best) return excluded ? false : null;
  const shown = ranges.slice(0, 3).join('; ');
  if (fits) {
    return { confidence: best.conf, reason: `CPE data: ${best.reason}`, note: `may affect: version ${sw.version} falls in the listed range (${shown}); check the vendor advisory` };
  }
  const why = sw.version ? `could not compare version ${sw.version} with (${shown})` : `no version recorded for this entry (affected: ${shown})`;
  return { confidence: demote(best.conf), reason: `CPE data: ${best.reason}`, note: `may affect: ${why}; check your version` };
}

function matchVendorProduct(adv, sw) {
  if (!adv.vendor && !adv.product) return null;
  const d = nameDecision(adv.vendor, adv.product, sw);
  if (!d) return null;
  const v = sw.version ? `version ${sw.version}` : 'your version';
  return { confidence: d.conf, reason: `Vendor/product: ${d.reason}`, note: `may affect: this source lists no version ranges; check ${v} against the vendor advisory` };
}

function matchOsv(adv, sw) {
  const x = adv.extra;
  if (!x?.pkg || x.pkg.toLowerCase() !== sw.name.toLowerCase() || (x.ecosystem || '') !== (sw.ecosystem || '')) return null;
  if (x.version !== sw.version) return null;
  return {
    confidence: 'high',
    reason: `OSV was queried for ${x.ecosystem} package "${x.pkg}" at version ${x.version} and returned this`,
    note: `may affect: version ${sw.version}; check whether a fixed release exists`,
  };
}

function matchText(adv, sw) {
  const text = new Set(tokens(`${adv.title} ${adv.summary || ''}`));
  const nameToks = tokens(sw.name).filter((t) => !/^\d+$/.test(t));
  const named = nameToks.length && compact(nameToks.join('')).length >= 4 && nameToks.every((t) => text.has(t));
  if (named) {
    return { confidence: 'medium', reason: `all words of "${sw.name}" appear in the item's headline or summary`, note: `may affect: read the item and check version ${sw.version || '(unknown)'}` };
  }
  if (adv.vendor && vendorMatch(adv.vendor, sw) && nameToks.some((t) => t.length >= 4 && text.has(t))) {
    return { confidence: 'low', reason: `item comes from your "${adv.vendor}" feed and mentions "${nameToks.find((t) => t.length >= 4 && text.has(t))}" from "${sw.name}"`, note: 'may be related; read the item' };
  }
  return null;
}

export function matchAdvisory(adv, sw) {
  if (adv.sources.includes('osv')) return matchOsv(adv, sw);
  if (adv.sources.includes('rss')) return matchText(adv, sw);
  const byCpe = adv.cpes.length ? matchCpes(adv, sw) : null;
  if (byCpe === false) return null;
  return byCpe || matchVendorProduct(adv, sw);
}
