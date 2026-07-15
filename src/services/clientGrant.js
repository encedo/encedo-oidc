import redis from './redis.js';

/**
 * Normalise a clients[] grant: drop duplicates and verify every client_id really
 * exists in the `clients` set. A well-formed UUID that names no client would be
 * stored happily, show up in the admin panel as a bare UUID with no name, and
 * authorise nothing -- the user simply could never sign in to it.
 *
 * Shared by POST/PATCH /admin/users and POST /admin/invite so there is a single
 * definition of "a valid grant" and no path can store a dangling client_id.
 *
 * @param {string[]|undefined} clients
 * @returns {Promise<{ids: string[], unknown: string[]}>}
 */
export async function resolveClientGrant(clients) {
  const ids = [...new Set(clients ?? [])];
  if (ids.length === 0) return { ids, unknown: [] };

  const pipeline = redis.multi();
  for (const id of ids) pipeline.sIsMember('clients', id);
  const exists = await pipeline.exec();

  return { ids, unknown: ids.filter((_, i) => !exists[i]) };
}
