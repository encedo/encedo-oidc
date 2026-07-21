import { createClient } from 'redis';

const REDIS_URL = process.env.REDIS_URL ?? 'redis://127.0.0.1:6379';

const client = createClient({
  url: REDIS_URL,
  socket: {
    // Bounded retry: tolerate a startup race (Redis coming up alongside the app),
    // but give up after ~20 attempts so connect() rejects instead of retrying
    // forever -- the catch below then exits cleanly. Default strategy never gives
    // up, which would hang startup when Redis is truly absent.
    reconnectStrategy: (retries) =>
      retries >= 10 ? new Error('Redis unreachable') : Math.min(retries * 100, 500),
  },
});

client.on('error', (err) => console.error('[Redis] Error:', err));
client.on('connect', () => console.log('[Redis] Connected'));
client.on('reconnecting', () => console.warn('[Redis] Reconnecting...'));

try {
  await client.connect();
} catch (err) {
  // Redis is the only datastore -- there is nothing to serve without it. Fail
  // fast with a clear message instead of an unhandled top-level rejection.
  console.error(`[Redis] Cannot connect to ${REDIS_URL}: ${err.message}`);
  process.exit(1);
}

export default client;
