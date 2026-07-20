// Unit tests for the input validators. node:test -- no dependencies.
//   npm test   (or: node --test test/validate.test.js)
//
// Every validator returns null when valid, or an error string. Tests assert on
// null vs "truthy string", and spot-check a couple of messages.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  vRequired, vOptional, vEmail, vUrl, vUsername, vDisplayName,
  vCodeChallenge, vCodeVerifier, vState, vNonce, vSignature,
  vKeyType, vTtl, vUuid, vClaimKey, validate,
} from '../src/middleware/validate.js';

const ok  = (r, msg) => assert.equal(r, null, msg ?? `expected valid, got: ${r}`);
const bad = (r, msg) => assert.equal(typeof r, 'string', msg ?? 'expected an error string');

test('vRequired', () => {
  ok(vRequired('hello', 'x'));
  bad(vRequired('', 'x'));
  bad(vRequired('   ', 'x'));          // whitespace-only
  bad(vRequired(undefined, 'x'));
  bad(vRequired(123, 'x'));            // non-string
  bad(vRequired('a'.repeat(257), 'x'));// over default max
  ok(vRequired('a'.repeat(10), 'x', 10));
  bad(vRequired('a'.repeat(11), 'x', 10));
});

test('vOptional', () => {
  ok(vOptional(undefined, 'x'));
  ok(vOptional(null, 'x'));
  ok(vOptional('', 'x'));              // empty allowed (present but not required non-empty)
  ok(vOptional('value', 'x'));
  bad(vOptional(123, 'x'));            // non-string
  bad(vOptional('a'.repeat(300), 'x'));
});

test('vEmail', () => {
  ok(vEmail('alice@example.com'));
  ok(vEmail('a.b+c@sub.example.co'));
  bad(vEmail('plainaddress'));
  bad(vEmail('a@b'));                  // no TLD dot
  bad(vEmail('a@.com'));               // empty domain label before dot
  bad(vEmail('@example.com'));         // empty local part
  bad(vEmail('a b@example.com'));      // space
  bad(vEmail(''));                     // required
  assert.match(vEmail('nope'), /valid email/);
});

test('vUrl', () => {
  ok(vUrl('https://my.ence.do'));
  ok(vUrl('http://192.168.1.5:2999'));           // private http allowed by default
  bad(vUrl('ftp://host/x'));                      // not http/https
  bad(vUrl('not a url'));
  bad(vUrl('https://user:pass@host/'));          // credentials rejected
  // httpsOnly
  bad(vUrl('http://example.com', 'hsm', { httpsOnly: true }));
  ok(vUrl('https://example.com', 'hsm', { httpsOnly: true }));
  ok(vUrl('http://localhost:3000', 'hsm', { httpsOnly: true, allowLocalhost: true }));
  bad(vUrl('http://example.com', 'hsm', { httpsOnly: true, allowLocalhost: true })); // not localhost
});

test('vUsername', () => {
  ok(vUsername('alice'));
  ok(vUsername('a.b_c-d@e'));          // @ is allowed
  bad(vUsername('a'));                 // too short (min 2)
  bad(vUsername('has space'));
  bad(vUsername('has#hash'));
  bad(vUsername('a'.repeat(65)));      // too long
  bad(vUsername(''));
});

test('vDisplayName (optional, max 128)', () => {
  ok(vDisplayName(undefined));
  ok(vDisplayName('Jan Kowalski'));
  bad(vDisplayName('n'.repeat(129)));
});

test('vCodeChallenge / vCodeVerifier (PKCE, 43-128 base64url)', () => {
  const good = 'A'.repeat(43);
  ok(vCodeChallenge(good));
  ok(vCodeChallenge(undefined));       // optional
  bad(vCodeChallenge('A'.repeat(42))); // too short
  bad(vCodeChallenge('has/slash+plus==='));
  ok(vCodeVerifier(good));
  ok(vCodeVerifier(''));               // optional
  bad(vCodeVerifier('short'));
});

test('vState / vNonce (optional, length-capped)', () => {
  ok(vState(undefined));
  ok(vState('xyz'));
  bad(vState('s'.repeat(513)));
  ok(vNonce('n'.repeat(256)));
  bad(vNonce('n'.repeat(257)));
});

test('vSignature (base64url 64-200)', () => {
  ok(vSignature('A'.repeat(86)));      // Ed25519 length
  bad(vSignature('A'.repeat(63)));     // too short
  bad(vSignature('has+plus/slash==' + 'A'.repeat(70))); // non-base64url chars
  bad(vSignature(''));                 // required
});

test('vKeyType', () => {
  for (const t of ['Ed25519', 'P256', 'P384', 'P521']) ok(vKeyType(t));
  ok(vKeyType(undefined));             // optional
  bad(vKeyType('RSA'));
  bad(vKeyType('ed25519'));            // case-sensitive
});

test('vTtl', () => {
  ok(vTtl(3600, 'ttl'));
  ok(vTtl('600', 'ttl'));              // numeric string
  bad(vTtl(59, 'ttl'));                // below min
  bad(vTtl(86401, 'ttl'));             // above max
  bad(vTtl('abc', 'ttl'));
  ok(vTtl(120, 'ttl', { min: 60, max: 200 }));
  bad(vTtl(201, 'ttl', { min: 60, max: 200 }));
});

test('vUuid (v4)', () => {
  ok(vUuid('0507afa8-ef36-4d85-8fec-6e6013f6cdba'));
  bad(vUuid('0507afa8-ef36-3d85-8fec-6e6013f6cdba')); // version digit not 4
  bad(vUuid('not-a-uuid'));
  bad(vUuid('0507afa8ef364d858fec6e6013f6cdba'));      // no dashes
  bad(vUuid(123));
});

test('vClaimKey', () => {
  ok(vClaimKey('department'));
  ok(vClaimKey('_private'));
  bad(vClaimKey('1leading_digit'));
  bad(vClaimKey('has-dash'));
  bad(vClaimKey('has space'));
  bad(vClaimKey('a'.repeat(65)));
});

test('validate() returns the first error or null', () => {
  assert.equal(validate(null, null, null), null);
  assert.equal(validate(null, 'first error', 'second'), 'first error');
  assert.equal(validate(vUsername('ok'), vEmail('a@b.com')), null);
  assert.equal(typeof validate(vUsername('ok'), vEmail('bad')), 'string');
});
