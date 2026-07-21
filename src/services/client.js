import { randomUUID, randomBytes } from 'crypto';

// Client credential + redirect-URI helpers shared by the admin CRUD routes
// (adminClients.js) and the client-invite signup flow (inviteClient.js).

export function generateClientSecret() { return randomBytes(32).toString('base64url'); }
export function generateClientId()     { return randomUUID(); }

// Validate a list of redirect URIs. Allows https:// anywhere and http:// only for
// localhost. Returns an error string for the first invalid URI, or null if all pass.
export function validateRedirectUris(uris) {
  for (const uri of uris) {
    try {
      const u = new URL(uri);
      if (u.protocol !== 'https:' && !(u.protocol === 'http:' && u.hostname === 'localhost')) {
        return `Non-localhost HTTP not allowed: ${uri}`;
      }
    } catch { return `Invalid URI: ${uri}`; }
  }
  return null;
}
