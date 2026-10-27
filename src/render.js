const dayOf = (iso) => (iso ? iso.slice(0, 10) : 'undated');

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

function tag(it) {
  const t = [];
  if (it.kev) t.push('KEV');
  if (it.severity) t.push(it.cvss ? `${it.severity} ${it.cvss}` : it.severity);
  t.push(`${it.confidence} confidence`);
  return t.join(', ');
}

function header(d) {
  const span = d.days ? `last ${d.days} days` : 'all stored advisories';
  const c = d.counts;
  return {
    title: `secdigest ${d.generated.slice(0, 10)}`,
    line: `${d.items.length} item(s) may affect your ${d.inventory} listed programs (${span}; ${d.scanned} advisories scanned). ` +
      `${c.kev} known-exploited, ${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low + c.unknown} low/unrated.`,
  };
}

export function renderText(d) {
  const h = header(d);
  const out = [h.title, h.line, `Outlook: ${d.weather.label}. ${d.weather.line}`, ''];
  if (!d.items.length) out.push('Nothing matched.');
  for (const it of d.items) {
    out.push(`[${tag(it)}] ${it.title}`);
    out.push(`  ${it.id}  ${dayOf(it.published)}  ${it.url || ''}`.trimEnd());
    for (const m of it.matches.slice(0, 5)) {
      out.push(`  - ${m.software.name} ${m.software.version}`.trimEnd() + ` (${m.confidence})`);
      out.push(`    why: ${m.reason}`);
      out.push(`    ${m.note}`);
    }
    if (it.matches.length > 5) out.push(`  ... and ${it.matches.length - 5} more`);
    out.push('');
  }
  return out.join('\n');
}

export function renderMarkdown(d) {
  const h = header(d);
  const out = [`# ${h.title}`, '', h.line, '', `Outlook: **${d.weather.label}**. ${d.weather.line}`, ''];
  if (!d.items.length) out.push('Nothing matched.');
  for (const it of d.items) {
    const link = it.url ? `[${it.id}](${it.url})` : it.id;
    out.push(`## ${it.title.replace(/[\r\n]+/g, ' ')}`, '', `${link} - ${dayOf(it.published)} - ${tag(it)}`, '');
    for (const m of it.matches.slice(0, 5)) {
      out.push(`- **${m.software.name} ${m.software.version}** (${m.confidence}): ${m.reason}. ${m.note}.`);
    }
    if (it.matches.length > 5) out.push(`- ... and ${it.matches.length - 5} more`);
    out.push('');
  }
  return out.join('\n');
}

export function renderHtml(d) {
  const h = header(d);
  const items = d.items.map((it) => `
<article class="${it.kev ? 'kev' : ''}">
<h2>${it.url ? `<a href="${esc(it.url)}">${esc(it.title)}</a>` : esc(it.title)}</h2>
<p class="meta">${esc(it.id)} &middot; ${esc(dayOf(it.published))} &middot; ${esc(tag(it))}</p>
<ul>${it.matches.slice(0, 5).map((m) => `<li><b>${esc(m.software.name)} ${esc(m.software.version)}</b> (${esc(m.confidence)}): ${esc(m.reason)}. ${esc(m.note)}.</li>`).join('')}</ul>
</article>`).join('');
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>${esc(h.title)}</title>
<style>
body{font:16px/1.5 system-ui,sans-serif;max-width:46em;margin:2em auto;padding:0 1em}
article{border-top:1px solid #aaa;padding:.5em 0}article.kev h2{color:#b00020}
h2{font-size:1.1em;margin:.2em 0}.meta{margin:0;color:#555;font-size:.85em}a{color:inherit}
</style></head><body>
<h1>${esc(h.title)}</h1><p>${esc(h.line)}</p><p>Outlook: <b>${esc(d.weather.label)}</b>. ${esc(d.weather.line)}</p>
${items || '<p>Nothing matched.</p>'}
</body></html>
`;
}
