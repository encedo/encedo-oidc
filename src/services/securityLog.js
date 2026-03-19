/**
 * Security event logger.
 * Publishes to Redis Pub/Sub (real-time consumers) and stores in ZSET (retention).
 *
 * Channel : security:events   <- subscribe for real-time stream
 * ZSET    : security:log      <- sorted by timestamp ms, queryable via ZRANGEBYSCORE
 *
 * Consumer example (separate process):
 *   const sub = redisClient.duplicate();
 *   await sub.connect();
 *   await sub.subscribe('security:events', (msg) => console.log(JSON.parse(msg)));
 */
import redis from './redis.js';

const CHANNEL = 'security:events';
const ZSET    = 'security:log';
const MAX     = parseInt(process.env.SECURITY_LOG_MAX ?? '20000', 10);

/**
 * @param {string} type  -- event type (see EVENT_TYPES below)
 * @param {object} data  -- arbitrary context fields
 */
export async function logSecurity(type, data = {}) {
  const entry = JSON.stringify({
    ts:   Date.now(),
    type,
    ...data,
  });

  // Synchronous stderr write -- captured by journald/Docker regardless of Redis state
  process.stderr.write(entry + '\n');

  try {
    // Real-time pub/sub -- for streaming consumers / SIEM
    await redis.publish(CHANNEL, entry);

    // Persistent ZSET -- score = ms timestamp, value = JSON
    await redis.zAdd(ZSET, { score: Date.now(), value: entry });

    // Trim oldest entries beyond MAX
    await redis.zRemRangeByRank(ZSET, 0, -(MAX + 1));
  } catch (err) {
    // Log to stderr but NEVER throw -- logging must not break auth flow
    console.error('[SecLog] Write failed:', err.message);
  }
}

// --- Event type constants --------------------------------------
export const SEC = {
  // Auth flow
  LOGIN_OK:          'auth.login.ok',
  LOGIN_FAIL:        'auth.login.fail',
  SIG_FAIL:          'auth.signature.fail',
  SIG_OK:            'auth.signature.ok',
  TOKEN_ISSUED:      'auth.token.issued',
  // Admin
  ADMIN_AUTH_FAIL:   'admin.auth.fail',
  ADMIN_USER_CREATE: 'admin.user.create',
  ADMIN_USER_DELETE: 'admin.user.delete',
  ADMIN_USER_PATCH:  'admin.user.patch',
  ADMIN_CLIENT_CREATE: 'admin.client.create',
  ADMIN_CLIENT_PATCH:  'admin.client.patch',
  ADMIN_CLIENT_DELETE: 'admin.client.delete',
  ADMIN_SECRET_ROTATE: 'admin.client.rotate_secret',
  // Enrollment
  ENROLL_OK:         'enrollment.ok',
  ENROLL_FAIL:       'enrollment.fail',
  ENROLL_REGEN:      'enrollment.regen',
  // Session
  LOGOUT:            'auth.logout',
  // Rate limiting
  RATE_LIMIT:        'ratelimit.hit',
};
