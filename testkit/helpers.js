import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const fixture = (name) => readFileSync(fileURLToPath(new URL(`../test/fixtures/${name}`, import.meta.url)), 'utf8');

// routes: path -> { body, type, etag } or a function(req) returning { status, body, headers }.
export async function fakeServer(routes) {
  const hits = [];
  const server = createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      hits.push({ path: req.url, method: req.method, headers: req.headers, body: raw });
      const path = req.url.split('?')[0];
      let r = routes[path];
      if (typeof r === 'function') r = r(req, raw);
      if (!r) { res.writeHead(404); return res.end('nope'); }
      if (r.etag && req.headers['if-none-match'] === r.etag) { res.writeHead(304); return res.end(); }
      res.writeHead(r.status || 200, { 'content-type': r.type || 'application/json', ...(r.etag ? { etag: r.etag } : {}), ...(r.headers || {}) });
      res.end(r.body);
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  return { base, hits, close: () => new Promise((r) => { server.closeAllConnections(); server.close(r); }) };
}
