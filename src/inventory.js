import { spawnSync } from 'node:child_process';

const REG_SCRIPT = `
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$keys = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
        'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
        'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
$rows = @(Get-ItemProperty -Path $keys | Where-Object { $_.DisplayName -and -not $_.SystemComponent } |
  ForEach-Object { [pscustomobject]@{ name = [string]$_.DisplayName; version = [string]$_.DisplayVersion; publisher = [string]$_.Publisher } })
ConvertTo-Json -InputObject $rows -Compress
`;

const TOOLS = [
  { name: 'Node.js', publisher: 'OpenJS Foundation', cmd: 'node', args: ['--version'] },
  { name: 'Python', publisher: 'Python Software Foundation', cmd: 'python', args: ['--version'] },
  { name: 'OpenJDK', publisher: 'Oracle', cmd: 'java', args: ['-version'] },
  { name: 'Git', publisher: 'Git project', cmd: 'git', args: ['--version'] },
  { name: 'CMake', publisher: 'Kitware', cmd: 'cmake', args: ['--version'] },
];

export function parseRegistryJson(text) {
  const clean = String(text).replace(/^\uFEFF/, '').trim();
  if (!clean) return [];
  let data;
  try {
    data = JSON.parse(clean);
  } catch {
    return [];
  }
  if (!Array.isArray(data)) data = [data];
  return data
    .filter((r) => r && typeof r.name === 'string' && r.name.trim())
    .map((r) => ({
      name: r.name.trim(),
      version: String(r.version ?? '').trim(),
      publisher: String(r.publisher ?? '').trim(),
      source: 'registry',
    }));
}

export function readRegistry() {
  if (process.platform !== 'win32') return [];
  const encoded = Buffer.from(REG_SCRIPT, 'utf16le').toString('base64');
  const r = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], {
    encoding: 'utf8', timeout: 60000, maxBuffer: 32 * 1024 * 1024, windowsHide: true,
  });
  if (r.error || r.status !== 0) return [];
  return parseRegistryJson(r.stdout);
}

// Columns are fixed-width; offsets come from the header line.
export function parseWingetList(text) {
  const lines = String(text).split(/\r?\n/).map((l) => l.replace(/^[\s\\|/-]+(?=Name\b)/, ''));
  const h = lines.findIndex((l) => /^Name\s+Id\s+Version/.test(l));
  if (h < 0 || !lines[h + 1] || !/^-{3,}/.test(lines[h + 1])) return [];
  const head = lines[h];
  const idCol = head.indexOf('Id');
  const verCol = head.indexOf('Version');
  const nextCols = ['Available', 'Source'].map((c) => head.indexOf(c)).filter((i) => i > verCol);
  const verEnd = nextCols.length ? Math.min(...nextCols) : Infinity;
  const out = [];
  for (const line of lines.slice(h + 2)) {
    if (!line.trim() || line.length <= verCol) continue;
    const name = line.slice(0, idCol).trim();
    const version = line.slice(verCol, verEnd).trim().replace(/^[<>~]\s*/, '');
    if (name) out.push({ name, version, publisher: '', source: 'winget' });
  }
  return out;
}

export function readWinget() {
  const r = spawnSync('winget', ['list', '--accept-source-agreements', '--disable-interactivity'], {
    encoding: 'utf8', timeout: 90000, maxBuffer: 32 * 1024 * 1024, windowsHide: true,
  });
  if (r.error || r.status !== 0) return [];
  return parseWingetList(r.stdout);
}

export function readToolchain() {
  const found = [];
  for (const t of TOOLS) {
    const r = spawnSync(t.cmd, t.args, { encoding: 'utf8', timeout: 8000, windowsHide: true });
    if (r.error || r.status !== 0) continue;
    const text = `${r.stdout}\n${r.stderr}`;
    const m = text.match(/(\d+(?:\.\d+)+)/);
    if (!m) continue;
    const name = t.cmd === 'java' && /openjdk/i.test(text) ? 'OpenJDK' : t.cmd === 'java' ? 'Java' : t.name;
    found.push({ name, version: m[1], publisher: t.publisher, source: 'toolchain' });
  }
  return found;
}

export function mergeScans(...lists) {
  const seen = new Set();
  const out = [];
  for (const e of lists.flat()) {
    const key = `${e.name.toLowerCase()}|${e.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(e);
  }
  return out;
}

export function scanInventory({ winget = true } = {}) {
  return mergeScans(readRegistry(), winget ? readWinget() : [], readToolchain());
}

function globToRegex(p) {
  const body = p.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*');
  return new RegExp(body, 'i');
}

export function isActive(sw, rules) {
  const hay = `${sw.name} ${sw.publisher}`;
  const allow = rules.filter((r) => r.kind === 'allow');
  if (rules.some((r) => r.kind === 'ignore' && globToRegex(r.pattern).test(hay))) return false;
  if (allow.length && !allow.some((r) => globToRegex(r.pattern).test(hay))) return false;
  return true;
}
