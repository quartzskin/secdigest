import { listAdvisories, listRules, listSoftware } from './db.js';
import { CONF_RANK, matchAdvisory } from './match.js';
import { isActive } from './inventory.js';

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

export function bucketOf(item) {
  if (item.kev || item.severity === 'critical') return 'critical';
  return item.severity || 'unknown';
}

function compareItems(a, b) {
  return (
    Number(b.kev) - Number(a.kev) ||
    b.confRank - a.confRank ||
    (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0) ||
    (b.cvss || 0) - (a.cvss || 0) ||
    String(b.published || '').localeCompare(String(a.published || ''))
  );
}

export function weatherOf(counts) {
  if (counts.kev) return { label: 'Stormy', line: 'Known-exploited flaws may touch software you have.' };
  if (counts.critical || counts.high) return { label: 'Unsettled', line: 'Serious advisories may apply; check the versions.' };
  if (counts.medium || counts.low) return { label: 'Overcast', line: 'Minor items only.' };
  return { label: 'Clear', line: 'Nothing in the feeds matched your inventory.' };
}

export function buildDigest(db, { days = 30, all = false, minConfidence = 'low', now = new Date() } = {}) {
  const rules = listRules(db);
  const software = listSoftware(db).filter((s) => isActive(s, rules));
  const cutoff = all ? 0 : now.getTime() - days * 86400000;
  const min = CONF_RANK[minConfidence] || 1;
  const advisories = listAdvisories(db);
  const items = [];
  for (const adv of advisories) {
    const when = Date.parse(adv.published || adv.seen);
    if (!all && !(when >= cutoff)) continue;
    const matches = [];
    for (const sw of software) {
      const m = matchAdvisory(adv, sw);
      if (!m || CONF_RANK[m.confidence] < min) continue;
      matches.push({
        software: { name: sw.name, version: sw.version, publisher: sw.publisher, source: sw.source },
        confidence: m.confidence, reason: m.reason, note: m.note,
      });
    }
    if (!matches.length) continue;
    matches.sort((a, b) => CONF_RANK[b.confidence] - CONF_RANK[a.confidence]);
    items.push({
      id: adv.id, title: adv.title, summary: adv.summary || '', url: adv.url,
      sources: adv.sources, severity: adv.severity, cvss: adv.cvss,
      kev: adv.kev, ransomware: adv.ransomware, published: adv.published,
      confidence: matches[0].confidence, confRank: CONF_RANK[matches[0].confidence], matches,
    });
  }
  items.sort(compareItems);
  for (const it of items) it.bucket = bucketOf(it);
  const counts = { kev: 0, critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const it of items) {
    counts[it.kev ? 'kev' : it.bucket]++;
  }
  return {
    generated: now.toISOString(),
    days: all ? null : days,
    inventory: software.length,
    scanned: advisories.length,
    counts,
    weather: weatherOf(counts),
    lead: items[0] || null,
    items,
  };
}
