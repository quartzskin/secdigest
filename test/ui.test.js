import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { listRules, openDb, replaceScanned } from '../src/db.js';
import { startServer } from '../src/ui.js';

function raw(url, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = request({ host: '127.0.0.1', port: u.port, path: u.pathname + u.search, method, headers }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

test('ui server: host and origin checks, token, security headers', async () => {
  const db = openDb(':memory:');
  replaceScanned(db, [{ name: 'Acme Widget Studio', version: '4.1.0', publisher: 'Acme', source: 'registry' }]);
  const srv = await startServer(db, { port: 0 });
  try {
    assert.match(srv.url, /^http:\/\/127\.0\.0\.1:\d+$/);
    const host = new URL(srv.url).host;

    const page = await raw(srv.url + '/');
    assert.equal(page.status, 200);
    assert.match(page.headers['content-security-policy'], /default-src 'none'/);
    assert.ok(page.body.includes(srv.token));
    assert.ok(!/https?:\/\/(?!127\.0\.0\.1)/.test(page.body.replace('http://www.w3.org', '')));

    assert.equal((await raw(srv.url + '/', { headers: { host: 'evil.example' } })).status, 403);
    assert.equal((await raw(srv.url + '/api/digest', { headers: { host: `evil.example:${new URL(srv.url).port}` } })).status, 403);

    const api = await raw(srv.url + '/api/digest?days=7&min=bogus');
    assert.equal(api.status, 200);
    assert.equal(JSON.parse(api.body).inventory, 1);
    assert.equal((await raw(srv.url + '/nope')).status, 404);

    const post = (headers, body = '{"pattern":"Acme*"}') =>
      raw(srv.url + '/api/ignore', { method: 'POST', headers: { host, 'content-type': 'application/json', ...headers }, body });
    assert.equal((await post({})).status, 403);
    assert.equal((await post({ origin: 'http://evil.example', 'x-secdigest-token': srv.token })).status, 403);
    assert.equal((await post({ origin: srv.url, 'x-secdigest-token': 'wrong' })).status, 403);
    assert.equal(listRules(db).length, 0);
    assert.equal((await post({ origin: srv.url, 'x-secdigest-token': srv.token }, 'not json')).status, 400);
    assert.equal((await post({ origin: srv.url, 'x-secdigest-token': srv.token }, '{"pattern":""}')).status, 400);
    assert.equal((await post({ origin: srv.url, 'x-secdigest-token': srv.token })).status, 200);
    assert.deepEqual(listRules(db).map((r) => ({ ...r })), [{ kind: 'ignore', pattern: 'Acme*' }]);
    assert.equal(JSON.parse((await raw(srv.url + '/api/digest')).body).inventory, 0);
    assert.equal((await raw(srv.url + '/', { method: 'DELETE' })).status, 405);
  } finally {
    await srv.close();
  }
});
