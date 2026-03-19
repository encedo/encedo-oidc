/**
 * Redis-based rate limiter -- works across multiple server instances.
 *
 * Usage:
 *   import { rateLimit } from './middleware/rateLimit.js';
 *   app.use('/authorize/login', rateLimit({ prefix: 'login', max: 10, window: 60 }));
 */
import redis from '../services/redis.js';
import { logSecurity, SEC } from '../services/securityLog.js';

/**
 * @param {object}   opts
 * @param {string}   opts.prefix   -- Redis key namespace (e.g. 'login')
 * @param {number}   opts.max      -- max requests per window
 * @param {number}   opts.window   -- window duration in seconds
 * @param {function} [opts.keyFn]  -- (req) -> string; default: client IP
 */
export function rateLimit({ prefix, max, window: windowSec, keyFn }) {
  return async (req, res, next) => {
    const id  = keyFn ? keyFn(req) : (req.ip ?? 'unknown');
    const key = `rl:${prefix}:${id}`;

    try {
      const count = await redis.incr(key);
      if (count === 1) await redis.expire(key, windowSec);

      const remaining = Math.max(0, max - count);
      res.setHeader('X-RateLimit-Limit',     String(max));
      res.setHeader('X-RateLimit-Remaining', String(remaining));

      if (count > max) {
        res.setHeader('Retry-After', String(windowSec));
        await logSecurity(SEC.RATE_LIMIT, { prefix, id, count });
        return res.status(429).json({ error: 'too_many_requests',
          error_description: `Rate limit exceeded. Retry after ${windowSec}s.` });
      }
    } catch {
      // Fail open -- Redis outage must not block authentication
    }

    next();
  };
}
