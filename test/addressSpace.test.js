// Address space of the HEM host (Local Network Access notice): pure classification.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ipSpace, normalizeHost, hostSpace } from '../src/services/addressSpace.js';

test('ipSpace: loopback, private / link-local / CGNAT, public', () => {
  for (const ip of ['127.0.0.1', '127.9.9.9', '::1']) assert.equal(ipSpace(ip), 'loopback', ip);
  for (const ip of ['10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.7.1', '169.254.1.1', '100.64.0.1', 'fd00::1', 'fc12::5', 'fe80::1', '::ffff:192.168.7.1'])
    assert.equal(ipSpace(ip), 'local', ip);
  for (const ip of ['8.8.8.8', '172.15.0.1', '172.32.0.1', '100.128.0.1', '2001:4860:4860::8888', '::ffff:8.8.8.8'])
    assert.equal(ipSpace(ip), 'public', ip);
  assert.throws(() => ipSpace('my.ence.do'));
});

test('normalizeHost: names and IP literals only', () => {
  assert.equal(normalizeHost('My.Ence.Do'), 'my.ence.do');
  assert.equal(normalizeHost('[::1]'), '::1');
  assert.equal(normalizeHost('192.168.7.1'), '192.168.7.1');
  for (const bad of ['', 'a b', 'http://x', 'x/y', '-x.com', 'a'.repeat(254), null, 42, 'x..y']) assert.equal(normalizeHost(bad), null, String(bad));
});

test('hostSpace: IP literals need no DNS; localhost resolves to loopback', async () => {
  assert.deepEqual(await hostSpace('192.168.7.1'), { space: 'local', addresses: ['192.168.7.1'] });
  assert.equal((await hostSpace('localhost')).space, 'loopback');
  assert.equal((await hostSpace('no-such-host.invalid')).space, 'unresolved');
});
