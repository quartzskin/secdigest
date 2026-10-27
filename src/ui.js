import { createServer } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { addRule } from './db.js';
import { buildDigest } from './digest.js';

const PAGE = readFileSync(fileURLToPath(new URL('./ui/index.html', import.meta.url)), 'utf8');

// Style and script are inline in the page, so the CSP allows exactly those blocks by hash.
const hashOf = (tag) => {
  const body = PAGE.match(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`))[1];
  return `'sha256-${createHash('sha256').update(body).digest('base64')}'`;
};
const CSP = `default-src 'none'; script-src ${hashOf('script')}; style-src ${hashOf('style')}; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`;

export function startServer(db, { port = 8787 } = {}) {
  const token = randomBytes(16).toString('hex');
  let origins = [];

  const send = (res, status, type, body) => {
    res.writeHead(status, {
      'content-type': type, 'content-security-policy': CSP, 'cache-control': 'no-store',
      'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer',
    });
    res.end(body);
  };

  const server = createServer((req, res) => {
    const hostOk = origins.some((o) => o.replace('http://', '') === req.headers.host);
    if (!hostOk) return send(res, 403, 'text/plain; charset=utf-8', 'bad host');
    const url = new URL(req.url, 'http://x');
    try {
      if (req.method === 'GET') {
        if (url.pathname === '/') {
          return send(res, 200, 'text/html; charset=utf-8', PAGE.replace('__TOKEN__', token));
        }
        if (url.pathname === '/api/digest') {
          const days = Math.min(Math.max(parseInt(url.searchParams.get('days'), 10) || 30, 1), 3650);
          const all = url.searchParams.get('all') === '1';
          const minConfidence = ['low', 'medium', 'high'].includes(url.searchParams.get('min')) ? url.searchParams.get('min') : 'low';
          return send(res, 200, 'application/json', JSON.stringify(buildDigest(db, { days, all, minConfidence })));
        }
        return send(res, 404, 'text/plain; charset=utf-8', 'not found');
      }
      if (req.method === 'POST' && url.pathname === '/api/ignore') {
        const origin = req.headers.origin;
        if (!origin || !origins.includes(origin) || req.headers['x-secdigest-token'] !== token) {
          return send(res, 403, 'text/plain; charset=utf-8', 'forbidden');
        }
        let body = '';
        req.on('data', (c) => { body += c; if (body.length > 4096) req.destroy(); });
        req.on('end', () => {
          let pattern;
          try { pattern = JSON.parse(body).pattern; } catch { /* handled below */ }
          if (typeof pattern !== 'string' || !pattern.trim() || pattern.length > 200) {
            return send(res, 400, 'text/plain; charset=utf-8', 'bad pattern');
          }
          addRule(db, 'ignore', pattern.trim());
          send(res, 200, 'application/json', '{"ok":true}');
        });
        return undefined;
      }
      return send(res, 405, 'text/plain; charset=utf-8', 'method not allowed');
    } catch (err) {
      return send(res, 500, 'text/plain; charset=utf-8', 'internal error');
    }
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      const p = server.address().port;
      origins = [`http://127.0.0.1:${p}`, `http://localhost:${p}`];
      resolve({ server, url: origins[0], token, close: () => new Promise((r) => server.close(r)) });
    });
  });
}

export function openBrowser(url, browser) {
  const exe = browser || process.env.BROWSER;
  const child = exe
    ? spawn(exe, [url], { detached: true, stdio: 'ignore' })
    : spawn('cmd.exe', ['/c', 'start', '', url], { detached: true, stdio: 'ignore', windowsHide: true });
  child.on('error', () => {});
  child.unref();
}
