'use strict';

const token = document.querySelector('meta[name="secdigest-token"]').content;
const SECTIONS = [
  ['critical', 'Exploited and critical'],
  ['high', 'High'],
  ['medium', 'Medium'],
  ['low', 'Low and unrated'],
];

function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'class') n.className = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const kid of kids.flat()) if (kid != null) n.append(kid);
  return n;
}

const day = (iso) => (iso ? iso.slice(0, 10) : 'undated');
const clip = (s, n) => (s.length > n ? s.slice(0, n - 1).replace(/\s+\S*$/, '') + '...' : s);
const headline = (it) => it.title.replace(/^(CVE-\d{4}-\d+|[A-Z]+-[\w-]+):\s*/, '');

function kicker(it) {
  const k = el('div', { class: 'kicker' });
  if (it.kev) k.append(el('span', { class: 'kev' }, 'Exploited'));
  const sev = it.severity ? it.severity + (it.cvss ? ' ' + it.cvss : '') : 'unrated';
  k.append(sev + ' \u00b7 ', el('span', { class: 'c-' + it.confidence }, it.confidence + ' match'));
  return k;
}

function affects(it) {
  const m = it.matches[0];
  const more = it.matches.length > 1 ? ' and ' + (it.matches.length - 1) + ' more' : '';
  return 'May affect: ' + m.software.name + (m.software.version ? ' ' + m.software.version : '') + more;
}

function story(it) {
  const open = () => showClip(it);
  return el('article', { class: 'story', tabindex: '0', role: 'button', onclick: open,
    onkeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } } },
    kicker(it), el('h3', null, clip(headline(it), 110)), el('p', { class: 'ex' }, clip(it.summary || '', 120)), el('p', null, affects(it)));
}

function lead(it) {
  const open = () => showClip(it);
  return el('article', { class: 'lead', tabindex: '0', role: 'button', onclick: open,
    onkeydown: (e) => { if (e.key === 'Enter') open(); } },
    kicker(it), el('h2', null, clip(headline(it), 150)),
    el('p', { class: 'byline' }, it.id + ' \u00b7 ' + day(it.published) + ' \u00b7 ' + it.sources.join(', ')),
    el('div', { class: 'body' }, clip(it.summary || 'No summary was supplied with this item.', 700)),
    el('div', { class: 'affects' }, affects(it)));
}

function weather(d) {
  const c = d.counts;
  const rows = [['Known exploited', c.kev], ['Critical', c.critical], ['High', c.high], ['Medium', c.medium], ['Low / unrated', c.low + c.unknown]];
  return el('section', { class: 'weather' }, el('div', { class: 'box' },
    el('h2', null, 'Weather'),
    el('p', { class: 'outlook ' + d.weather.label }, d.weather.label),
    el('p', { class: 'line' }, d.weather.line),
    el('table', null, rows.map(([n, v]) => el('tr', null, el('td', null, n), el('td', null, String(v))))),
    el('p', { class: 'small' }, d.inventory + ' programs listed, ' + d.scanned + ' advisories on file.')));
}

function render(d) {
  const front = document.getElementById('front');
  front.replaceChildren();
  document.getElementById('stamp').textContent = 'Compiled ' + d.generated.slice(11, 16) + ' UTC';
  if (!d.items.length) {
    front.append(el('div', { class: 'top' }, el('div', { class: 'empty' },
      d.scanned ? 'Quiet day: nothing on file matches your software.' : 'No advisories on file yet. Run "secdigest update" first.'), weather(d)));
    return;
  }
  front.append(el('div', { class: 'top' }, lead(d.items[0]), weather(d)));
  const rest = d.items.slice(1);
  front.append(el('div', { class: 'cols' }, SECTIONS.map(([key, title]) => {
    const list = rest.filter((it) => (key === 'low' ? it.bucket === 'low' || it.bucket === 'unknown' : it.bucket === key));
    return el('section', { class: 'col' }, el('h2', null, title + ' (' + list.length + ')'),
      list.length ? list.slice(0, 40).map(story) : el('p', { class: 'none' }, 'Nothing in this column.'));
  })));
}

function showClip(it) {
  const box = document.getElementById('clip');
  const close = () => { box.hidden = true; };
  box.replaceChildren(
    el('button', { class: 'close', onclick: close }, 'Close'),
    kicker(it),
    el('h2', null, headline(it)),
    el('div', { class: 'meta' }, it.id + ' \u00b7 ' + day(it.published) + ' \u00b7 from ' + it.sources.join(', ')),
    el('p', null, clip(it.summary || 'No summary supplied.', 1200)),
    it.url ? el('p', null, el('a', { href: it.url, rel: 'noreferrer noopener', target: '_blank' }, 'Read the source')) : null,
    el('h3', null, 'Matched software'),
    it.matches.map((m) => el('div', { class: 'why' },
      el('h4', null, m.software.name + (m.software.version ? ' ' + m.software.version : '') + ' (' + m.confidence + ' confidence)'),
      m.software.publisher ? el('p', { class: 'meta' }, m.software.publisher + ' \u00b7 found via ' + m.software.source) : null,
      el('p', null, 'Why: ' + m.reason + '.'),
      el('p', { class: 'note' }, m.note + '.'),
      el('button', { onclick: () => ignore(m.software.name, close) }, 'Not mine, ignore this program'))));
  box.hidden = false;
  box.scrollTop = 0;
}

async function ignore(name, close) {
  const res = await fetch('/api/ignore', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-secdigest-token': token },
    body: JSON.stringify({ pattern: name }),
  });
  if (res.ok) { close(); load(); }
}

async function load() {
  const q = new URLSearchParams({
    days: document.getElementById('days').value,
    min: document.getElementById('min').value,
    all: document.getElementById('all').checked ? '1' : '0',
  });
  const front = document.getElementById('front');
  try {
    const res = await fetch('/api/digest?' + q);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    render(await res.json());
  } catch (err) {
    front.replaceChildren(el('p', { class: 'empty' }, 'The presses are down: ' + err.message));
  }
}

const now = new Date();
document.getElementById('dateline').textContent =
  now.toLocaleDateString('en-GB', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });
const start = new Date(now.getFullYear(), 0, 0);
document.getElementById('edition').textContent = 'Vol. I \u00b7 No. ' + Math.floor((now - start) / 86400000);
for (const id of ['days', 'min', 'all']) document.getElementById(id).addEventListener('change', load);
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') document.getElementById('clip').hidden = true; });
load();
