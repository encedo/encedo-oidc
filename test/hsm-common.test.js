// Unit tests for the browser helper module -- it is DOM- and SDK-free, so it
// loads in Node as-is. atob/btoa/TextDecoder/fetch are globals in Node 18+.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import { checkP1363, decodeJwtPayload, decodeJwtHeader, hemErrMsg, fetchJson, bytesToBase64url, bytesToHex, base64ToBytes } from '../hsm-common.js';

test('checkP1363 passes a raw r||s signature (HEM FW 1.3) that Node verifies as ieee-p1363', () => {
  for (const [keyType, curve, hash] of [['P256', 'prime256v1', 'sha256'], ['P384', 'secp384r1', 'sha384'], ['P521', 'secp521r1', 'sha512']]) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: curve });
    const msg = Buffer.from('signing_input');
    const raw = new Uint8Array(crypto.sign(hash, msg, { key: privateKey, dsaEncoding: 'ieee-p1363' }));
    const out = checkP1363(raw, keyType);
    assert.equal(out, raw, `${keyType}: passed through unchanged`);
    assert.ok(crypto.verify(hash, msg, { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(out)), `${keyType}: verifies`);
  }
});

test('checkP1363 refuses DER (pre-1.3 firmware) and wrong lengths', () => {
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const der = new Uint8Array(crypto.sign('sha256', Buffer.from('m'), { key: privateKey, dsaEncoding: 'der' }));
  assert.throws(() => checkP1363(der, 'P256'), /64-byte r\|\|s/);
  assert.throws(() => checkP1363(new Uint8Array(96), 'P256'), /got 96 bytes/);
  assert.throws(() => checkP1363(new Uint8Array(64), 'X'), /unsupported/);
  assert.throws(() => checkP1363('AAAA', 'P256'), /expected/);
});

test('JWT parts decode as UTF-8 (no mojibake for non-ASCII names)', () => {
  const header  = { alg: 'EdDSA', kid: 'k1' };
  const payload = { sub: 's', name: 'Łukasz Żółć', email: 'ł@ex.pl' };
  const b64 = o => Buffer.from(JSON.stringify(o)).toString('base64url');
  const signingInput = `${b64(header)}.${b64(payload)}`;
  assert.deepEqual(decodeJwtHeader(signingInput), header);
  assert.deepEqual(decodeJwtPayload(signingInput), payload);
  assert.equal(decodeJwtPayload('not.a.jwt'), null);
});

test('byte helpers round-trip', () => {
  const bytes = new Uint8Array([0, 1, 250, 255, 62, 63]);
  assert.equal(bytesToHex(bytes), '0001faff3e3f');
  assert.equal(bytesToBase64url(bytes), Buffer.from(bytes).toString('base64url'));
  assert.deepEqual(base64ToBytes(Buffer.from(bytes).toString('base64')), bytes);
});

test('hemErrMsg maps SDK error codes to one message each', () => {
  assert.match(hemErrMsg({ code: 'http_401', message: 'x', status: 401 }), /passphrase/);
  assert.match(hemErrMsg({ code: 'denied',   message: 'x' }), /declined/);
  assert.match(hemErrMsg({ code: 'timeout',  message: 'x' }), /in time/);
  assert.match(hemErrMsg({ code: 'network',  message: 'x' }), /reach/);
  assert.match(hemErrMsg({ code: 'http_500', message: 'boom', status: 500 }), /http_500.*boom/);
  assert.match(hemErrMsg(new Error('plain')), /plain/);
});

test('fetchJson turns a proxy HTML error page and JSON errors into one Error shape', async () => {
  const srv = http.createServer((req, res) => {
    if (req.url === '/html') { res.writeHead(502, { 'Content-Type': 'text/html' }); res.end('<html>Bad gateway</html>'); }
    else if (req.url === '/err') { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'invalid_request', error_description: 'missing foo' })); }
    else { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('{"ok":true}'); }
  });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    assert.deepEqual(await fetchJson(base + '/ok'), { ok: true });
    await assert.rejects(fetchJson(base + '/html'), e => e.status === 502 && /HTTP 502/.test(e.message) && e.data === null);
    await assert.rejects(fetchJson(base + '/err'),  e => e.status === 400 && e.code === 'invalid_request' && e.message === 'missing foo');
  } finally { srv.close(); }
});
