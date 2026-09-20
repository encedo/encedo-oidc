import { createClient } from 'redis';

const REDIS_URL = process.env.REDIS_URL ?? 'redis://127.0.0.1:6379';

// Two reconnect regimes, because node-redis applies ONE strategy for the whole
// life of the client and returning an Error from it closes the socket for
// good (isOpen=false, every later command throws ClientClosedError, no more
// attempts):
//  - before the first successful connection: bounded. Tolerates a startup race
//    (Redis coming up alongside the app) but gives up after ~3.5 s so
//    connect() rejects and the process exits with a clear message instead of
//    hanging when Redis is truly absent.
//  - afterwards: forever, capped backoff. A Redis restart, a BGSAVE stall or a
//    brief OOM must not turn into a permanently dead process that still
//    answers /health with 200 (which is exactly what the bounded strategy did).
let everReady = false;

const client = createClient({
  url: REDIS_URL,
  socket: {
    reconnectStrategy: (retries) => {
      if (!everReady) return retries >= 10 ? new Error('Redis unreachable') : Math.min(retries * 100, 500);
      return Math.min(200 * retries, 5_000);
    },
  },
});

client.on('error', (err) => console.error('[Redis] Error:', err.message ?? err));
client.on('ready', () => { everReady = true; console.log('[Redis] Connected'); });
client.on('reconnecting', () => console.warn('[Redis] Reconnecting...'));

try {
  await client.connect();
} catch (err) {
  // Redis is the only datastore -- there is nothing to serve without it. Fail
  // fast with a clear message instead of an unhandled top-level rejection.
  console.error(`[Redis] Cannot connect to ${REDIS_URL}: ${err.message}`);
  process.exit(1);
}

/**
 * Liveness probe for /health: true only when the socket is up AND a PING is
 * answered within `timeoutMs`. Commands issued while the client is
 * reconnecting sit in the offline queue, so a bare ping() could hang for as
 * long as the outage lasts -- the race keeps the probe bounded.
 */
export async function redisAlive(timeoutMs = 1_000) {
  if (!client.isReady) return false;
  let timer;
  try {
    const pong = await Promise.race([
      client.ping(),
      new Promise((_, rej) => { timer = setTimeout(() => rej(new Error('ping timeout')), timeoutMs); }),
    ]);
    return pong === 'PONG';
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

export default client;
