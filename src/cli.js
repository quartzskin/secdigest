import {
  addFeed, addManual, addRule, listFeeds, listRules, listSoftware, openDb, removeFeed, removeManual,
  removeRule, replaceScanned,
} from './db.js';
import { scanInventory } from './inventory.js';
import { runUpdate, SOURCES } from './update.js';
import { buildDigest } from './digest.js';
import { renderHtml, renderMarkdown, renderText } from './render.js';
import { openBrowser, startServer } from './ui.js';

const HELP = `secdigest - security advisories filtered to software you have installed

  secdigest inventory [--no-winget]        scan installed software and store it
  secdigest inventory list
  secdigest inventory add <name> [version] [--publisher P] [--ecosystem npm|PyPI|...]
  secdigest inventory remove <name>        manual entries only
  secdigest inventory ignore <pattern>     never match this program (* allowed)
  secdigest inventory allow <pattern>      only match programs fitting an allow pattern
  secdigest inventory unrule <pattern>
  secdigest inventory rules
  secdigest feeds add <url> [--vendor V]   RSS/Atom feed to follow on update
  secdigest feeds list | feeds remove <url>
  secdigest update [--only kev,nvd,osv,rss] [--days N] [--dry-run]
  secdigest digest [--format text|md|html] [--days N] [--all] [--min low|medium|high] [--out FILE]
  secdigest ui [--port N] [--no-open] [--browser EXE]

Global: --db FILE (default %LOCALAPPDATA%\\secdigest\\secdigest.db, or SECDIGEST_DB)
Nothing touches the network except "update".
`;

const BOOL = new Set(['no-open', 'dry-run', 'all', 'no-winget', 'help']);

export function parseArgs(argv) {
  const pos = [];
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const [k, inline] = a.slice(2).split(/=(.*)/s);
      if (BOOL.has(k)) flags[k] = true;
      else if (inline !== undefined) flags[k] = inline;
      else if (i + 1 < argv.length) flags[k] = argv[++i];
      else flags[k] = '';
    } else pos.push(a);
  }
  return { pos, flags };
}

const intFlag = (v, dflt) => {
  const n = parseInt(v, 10);
  return Number.isFinite(n) && n > 0 ? n : dflt;
};

function table(rows) {
  return rows.map((r) => {
    const how = r.ecosystem ? `${r.source}, ${r.ecosystem}` : r.source;
    return `${r.name}  ${r.version}  ${r.publisher ? `[${r.publisher}] ` : ''}(${how})`;
  }).join('\n');
}

async function inventoryCmd(db, pos, flags, out) {
  const [sub, ...rest] = pos;
  if (!sub) {
    out('Reading the Uninstall registry keys, winget and toolchain versions (read-only)...');
    const found = scanInventory({ winget: !flags['no-winget'] });
    if (!found.length) {
      out('Nothing found; keeping the stored list. (Registry scan needs Windows PowerShell.)');
      return 1;
    }
    replaceScanned(db, found);
    const by = {};
    for (const f of found) by[f.source] = (by[f.source] || 0) + 1;
    out(`Stored ${found.length} entries: ${Object.entries(by).map(([k, v]) => `${v} ${k}`).join(', ')}.`);
    return 0;
  }
  if (sub === 'list') {
    const rows = listSoftware(db);
    out(rows.length ? table(rows) : 'Inventory is empty. Run "secdigest inventory".');
    return 0;
  }
  if (sub === 'add') {
    if (!rest[0]) { out('usage: inventory add <name> [version]'); return 2; }
    addManual(db, { name: rest[0], version: rest[1] || '', publisher: flags.publisher || '', ecosystem: flags.ecosystem || '' });
    out(`Added manual entry ${rest[0]} ${rest[1] || ''}`.trim());
    return 0;
  }
  if (sub === 'remove') {
    const n = rest[0] ? removeManual(db, rest[0]) : 0;
    out(n ? `Removed ${n} manual entr${n === 1 ? 'y' : 'ies'}.` : 'No manual entry by that name.');
    return n ? 0 : 1;
  }
  if (sub === 'ignore' || sub === 'allow') {
    if (!rest[0]) { out(`usage: inventory ${sub} <pattern>`); return 2; }
    addRule(db, sub, rest[0]);
    out(`Rule saved: ${sub} ${rest[0]}`);
    return 0;
  }
  if (sub === 'unrule') {
    const n = rest[0] ? removeRule(db, rest[0]) : 0;
    out(n ? 'Rule removed.' : 'No such rule.');
    return n ? 0 : 1;
  }
  if (sub === 'rules') {
    const rules = listRules(db);
    out(rules.length ? rules.map((r) => `${r.kind} ${r.pattern}`).join('\n') : 'No allow/ignore rules.');
    return 0;
  }
  out(`unknown inventory command: ${sub}`);
  return 2;
}

function feedsCmd(db, pos, flags, out) {
  const [sub, url] = pos;
  if (sub === 'add') {
    if (!/^https?:\/\//i.test(url || '')) { out('usage: feeds add <http(s) url> [--vendor V]'); return 2; }
    addFeed(db, url, flags.vendor || '');
    out(`Feed saved. It is fetched on "secdigest update", not before.`);
    return 0;
  }
  if (sub === 'remove') {
    const n = url ? removeFeed(db, url) : 0;
    out(n ? 'Feed removed.' : 'No such feed.');
    return n ? 0 : 1;
  }
  if (sub === 'list' || !sub) {
    const feeds = listFeeds(db);
    out(feeds.length ? feeds.map((f) => `${f.url}${f.vendor ? `  (vendor: ${f.vendor})` : ''}`).join('\n') : 'No RSS feeds configured.');
    return 0;
  }
  out(`unknown feeds command: ${sub}`);
  return 2;
}

async function updateCmd(db, flags, out) {
  const only = flags.only ? flags.only.split(',').map((s) => s.trim().toLowerCase()) : SOURCES;
  const bad = only.filter((s) => !SOURCES.includes(s));
  if (bad.length) { out(`unknown source: ${bad.join(', ')} (choose from ${SOURCES.join(', ')})`); return 2; }
  const dryRun = !!flags['dry-run'];
  out(dryRun ? 'Dry run: no requests will be sent.' : 'Fetching feeds (this is the only command that uses the network)...');
  const results = await runUpdate(db, { only, dryRun, days: intFlag(flags.days, 2), delayMs: flags['delay-ms'] != null ? Number(flags['delay-ms']) : undefined });
  let failed = 0;
  for (const r of results) {
    if (r.error) failed++;
    out(`${r.name.padEnd(4)} ${r.error ? `FAILED: ${r.error}` : 'ok'}${r.detail ? `${r.error ? ' | ' : ' - '}${r.detail}` : ''}`);
  }
  return failed ? 1 : 0;
}

function digestCmd(db, flags, out, write) {
  const format = flags.format || 'text';
  const render = { text: renderText, md: renderMarkdown, markdown: renderMarkdown, html: renderHtml }[format];
  if (!render) { out(`unknown format: ${format}`); return 2; }
  const min = ['low', 'medium', 'high'].includes(flags.min) ? flags.min : 'low';
  const d = buildDigest(db, { days: intFlag(flags.days, 30), all: !!flags.all, minConfidence: min });
  const text = render(d);
  if (flags.out) {
    write(flags.out, text);
    out(`Wrote ${flags.out} (${d.items.length} item(s)).`);
  } else out(text);
  return 0;
}

async function uiCmd(db, flags, out) {
  const port = flags.port !== undefined ? Number(flags.port) : 8787;
  if (!Number.isInteger(port) || port < 0 || port > 65535) { out('bad --port'); return 2; }
  let srv;
  try {
    srv = await startServer(db, { port });
  } catch (err) {
    out(`Could not listen on 127.0.0.1:${port}: ${err.code || err.message}`);
    return 1;
  }
  out(`Serving ${srv.url} (loopback only). Ctrl+C to stop.`);
  if (!flags['no-open']) openBrowser(srv.url, flags.browser);
  await new Promise((resolve) => process.once('SIGINT', resolve));
  await srv.close();
  return 0;
}

export async function main(argv, { out = (s) => console.log(s), write } = {}) {
  const { pos, flags } = parseArgs(argv);
  const [cmd, ...rest] = pos;
  if (!cmd || flags.help || cmd === 'help') { out(HELP); return cmd || flags.help ? 0 : 2; }
  const known = ['inventory', 'feeds', 'update', 'digest', 'ui'];
  if (!known.includes(cmd)) { out(`unknown command: ${cmd}\n\n${HELP}`); return 2; }
  const { writeFileSync } = await import('node:fs');
  const db = openDb(flags.db || undefined);
  try {
    switch (cmd) {
      case 'inventory': return await inventoryCmd(db, rest, flags, out);
      case 'feeds': return feedsCmd(db, rest, flags, out);
      case 'update': return await updateCmd(db, flags, out);
      case 'digest': return digestCmd(db, flags, out, write || ((f, t) => writeFileSync(f, t)));
      default: return await uiCmd(db, flags, out);
    }
  } finally {
    db.close();
  }
}
