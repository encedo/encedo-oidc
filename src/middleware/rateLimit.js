/**
 * Redis-based rate limiter -- works across multiple server instances.
 *
 * Usage:
 *   import { rateLimit } from './middleware/rateLimit.js';
 *   app.use('/authorize/login', rateLimit({ prefix: 'login', max: 10, window: 60 }));
 */
import { createHash } from 'crypto';
import redis from '../services/redis.js';
import { logSecurity, SEC } from '../services/securityLog.js';

// What the audit log sees as the limited identity. IPs, client_ids (UUID) and
// subs are fine to show; anything else (an enrollment token used as the key
// for /enrollment/*) is a credential and must not land in the log -- a short
// hash still lets the operator correlate repeated hits.
function loggableId(id) {
  return /^[0-9a-f.:-]+$/i.test(id) ? id : 'sha256:' + createHash('sha256').update(id).digest('hex').slice(0, 16);
}

/**
 * @param {object}   opts
 * @param {string}   opts.prefix   -- Redis key namespace (e.g. 'login')
 * @param {number}   opts.max      -- max requests per window
 * @param {number}   opts.window   -- window duration in seconds
 * @param {function} [opts.keyFn]  -- (req) -> string; default: client IP
 */
export function rateLimit({ prefix, max, window: windowSec, keyFn }) {
  return async (req, res, next) => {
    const id  = String(keyFn ? keyFn(req) : (req.ip ?? 'unknown'));
    const key = `rl:${prefix}:${id}`;

    try {
      // SET NX EX creates the counter WITH its expiry in one command, so the
      // key can never exist without a TTL (INCR-then-EXPIRE could lose the
      // EXPIRE to a dropped connection and leave a counter that only grows --
      // a permanent 429 for that key). The TTL read repairs any such counter
      // left behind by the old code.
      const [, count, ttl] = await redis.multi()
        .set(key, '0', { EX: windowSec, NX: true })
        .incr(key)
        .ttl(key)
        .exec();
      if (ttl === -1) await redis.expire(key, windowSec);

      const remaining = Math.max(0, max - count);
      res.setHeader('X-RateLimit-Limit',     String(max));
      res.setHeader('X-RateLimit-Remaining', String(remaining));

      if (count > max) {
        res.setHeader('Retry-After', String(windowSec));
        await logSecurity(SEC.RATE_LIMIT, { prefix, id: loggableId(id), count });
        return res.status(429).json({ error: 'too_many_requests',
          error_description: `Rate limit exceeded. Retry after ${windowSec}s.` });
      }
    } catch {
      // Fail open -- Redis outage must not block authentication
    }

    next();
  };
}
