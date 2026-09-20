// Unit tests for the browser helper module -- it is DOM- and SDK-free, so it
// loads in Node as-is. atob/btoa/TextDecoder/fetch are globals in Node 18+.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import { derToP1363, decodeJwtPayload, decodeJwtHeader, hemErrMsg, fetchJson, bytesToBase64url, bytesToHex, base64ToBytes } from '../hsm-common.js';

test('derToP1363 converts real ECDSA DER signatures that Node then verifies as ieee-p1363', () => {
  for (const [keyType, curve, hash] of [['P256', 'prime256v1', 'sha256'], ['P384', 'secp384r1', 'sha384'], ['P521', 'secp521r1', 'sha512']]) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: curve });
    const n = { P256: 32, P384: 48, P521: 66 }[keyType];
    for (let i = 0; i < 20; i++) {   // enough draws to hit high-bit r/s (sign padding) and short ones
      const msg = Buffer.from(`m${i}`);
      const der = new Uint8Array(crypto.sign(hash, msg, { key: privateKey, dsaEncoding: 'der' }));
      const p1363 = derToP1363(der, keyType);
      assert.equal(p1363.length, 2 * n, `${keyType}: fixed width`);
      assert.ok(crypto.verify(hash, msg, { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(p1363)), `${keyType}: verifies`);
    }
  }
});

test('derToP1363 refuses malformed input instead of returning garbage', () => {
  assert.throws(() => derToP1363(new Uint8Array(64), 'P256'), /DER SEQUENCE/);            // raw r||s, not DER
  assert.throws(() => derToP1363(new Uint8Array([0x30, 0x06, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00]), 'P256'), /INTEGER/);
  assert.throws(() => derToP1363(new Uint8Array([0x30, 0x08, 0x02, 0x40, ...new Array(6).fill(1)]), 'P256'), /length/);
  assert.throws(() => derToP1363(new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]), 'X'), /unsupported/);
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
