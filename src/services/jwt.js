import { createPublicKey, verify } from 'crypto';
import { verifyEd25519 } from './ed25519.js';

// Stateless JWT / signature / JWK helpers shared by the OIDC routes.
// No Redis, no request state -- pure crypto + encoding.

/** JWT `alg` value per key type. */
export const JWT_ALG = {
  Ed25519: 'EdDSA',
  P256:    'ES256',
  P384:    'ES384',
  P521:    'ES512',
};

/** Node.js hash for ECDSA verify. */
const ECDSA_HASH = { P256: 'sha256', P384: 'sha384', P521: 'sha512' };

/** JWK crv name for EC keys. */
const EC_CRV = { P256: 'P-256', P384: 'P-384', P521: 'P-521' };

const b64url          = buf => Buffer.from(buf).toString('base64url');
export const b64urlStr = str => Buffer.from(str).toString('base64url');

/**
 * Verify signature -- type-aware.
 * key_type  : 'Ed25519' | 'P256' | 'P384' | 'P521' (defaults to Ed25519)
 * pubkeyHex : hex-encoded raw public key bytes
 * message   : string that was signed
 * sigB64url : base64url signature from HSM
 */
export function verifySignature(key_type, pubkeyHex, message, sigB64url) {
  const pubBytes = Buffer.from(pubkeyHex, 'hex');
  const sigBuf   = Buffer.from(sigB64url, 'base64url');
  const msgBuf   = Buffer.from(message);

  if (!key_type || key_type === 'Ed25519') {
    return verifyEd25519(pubkeyHex, msgBuf, sigBuf);
  }

  // ECDSA: pubBytes = raw X||Y (no 04 prefix)
  const half = pubBytes.length / 2;
  const x    = pubBytes.subarray(0, half).toString('base64url');
  const y    = pubBytes.subarray(half).toString('base64url');
  const crv  = EC_CRV[key_type];
  const publicKey = createPublicKey({ key: { kty: 'EC', crv, x, y }, format: 'jwk' });
  return verify(ECDSA_HASH[key_type], msgBuf, { key: publicKey, dsaEncoding: 'ieee-p1363' }, sigBuf);
}

/**
 * Build a JWK entry from a user record.
 * key_type defaults to 'Ed25519' for backwards compatibility with old enrollments.
 */
export function buildJwk(u) {
  const kt = u.key_type || 'Ed25519';
  const pubBytes = Buffer.from(u.pubkey, 'hex');

  if (kt === 'Ed25519') {
    return {
      kty: 'OKP',
      crv: 'Ed25519',
      x:   b64url(pubBytes),
      kid: u.kid,
      alg: 'EdDSA',
      use: 'sig',
    };
  }

  // ECDSA: pubBytes = raw X||Y
  const half = pubBytes.length / 2;
  return {
    kty: 'EC',
    crv: EC_CRV[kt],
    x:   b64url(pubBytes.subarray(0, half)),
    y:   b64url(pubBytes.subarray(half)),
    kid: u.kid,
    alg: JWT_ALG[kt],
    use: 'sig',
  };
}
