import { createPublicKey, verify } from 'crypto';

// Fixed SPKI DER prefix for a raw 32-byte Ed25519 public key (RFC 8410).
// The HSM/Redis stores only the raw key; prepending this prefix reconstructs the
// SPKI wrapper that Node's crypto needs to import it.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

// Verify an Ed25519 signature.
//   pubkeyHex : raw 32-byte public key, hex-encoded (64 hex chars)
//   msgBuf    : Buffer of the signed message
//   sigBuf    : Buffer of the 64-byte signature
// Returns true/false. Never throws for a bad signature (only for a malformed key).
export function verifyEd25519(pubkeyHex, msgBuf, sigBuf) {
  const der       = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(pubkeyHex, 'hex')]);
  const publicKey = createPublicKey({ key: der, format: 'der', type: 'spki' });
  return verify(null, msgBuf, publicKey, sigBuf);
}
