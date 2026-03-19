import { timingSafeEqual } from 'crypto';

/**
 * Middleware: Admin Bearer token auth.
 * Uses timing-safe comparison to prevent timing attacks.
 */
export function requireAdminAuth(req, res, next) {
  const authHeader = req.headers['authorization'] ?? '';
  const token = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7).trim()
    : null;

  const secret = process.env.ADMIN_SECRET;
  if (!secret) {
    console.error('[Auth] ADMIN_SECRET is not set -- refusing all admin requests');
    return res.status(500).json({ error: 'server_misconfigured' });
  }

  if (!token) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  // Timing-safe comparison -- prevents secret length/value leakage via timing
  let valid = false;
  try {
    const a = Buffer.from(token,  'utf8');
    const b = Buffer.from(secret, 'utf8');
    valid = a.length === b.length && timingSafeEqual(a, b);
  } catch {
    valid = false;
  }

  if (!valid) {
    // Log failed attempt (logSecurity imported lazily to avoid circular dep)
    import('../services/securityLog.js').then(({ logSecurity, SEC }) =>
      logSecurity(SEC.ADMIN_AUTH_FAIL, { ip: req.ip })
    ).catch(() => {});
    return res.status(401).json({ error: 'unauthorized' });
  }

  next();
}

/**
 * Middleware: Restrict admin endpoints to allowed IPs.
 * Set ADMIN_ALLOWED_IPS=127.0.0.1,::1,10.0.0.0/8 (comma-separated, CIDR optional).
 * Default (when not set): localhost only (127.0.0.1 and ::1).
 */
export function requireAdminNetwork(req, res, next) {
  const allowedEnv = process.env.ADMIN_ALLOWED_IPS ?? '127.0.0.1,::1';

  const allowed = allowedEnv.split(',').map(s => s.trim()).filter(Boolean);
  // Normalise IPv6: strip IPv4-mapped prefix, collapse full-zero loopback form
  const clientIp = (req.ip ?? '')
    .replace(/^::ffff:/, '')
    .replace(/^0*:0*:0*:0*:0*:0*:0*:1$/, '::1');

  const ok = allowed.some(entry => ipMatches(clientIp, entry));
  if (!ok) {
    console.warn(`[Auth] Admin access denied for IP ${clientIp}`);
    return res.status(403).json({ error: 'forbidden' });
  }

  next();
}

/** Naive CIDR/exact match for IPv4. IPv6 literals matched exactly. */
function ipMatches(ip, entry) {
  if (!entry.includes('/')) return ip === entry;

  // CIDR match (IPv4 only)
  try {
    const [base, bits] = entry.split('/');
    const mask = ~((1 << (32 - parseInt(bits, 10))) - 1) >>> 0;
    const ipNum   = ipv4ToInt(ip.replace(/^::ffff:/, ''));
    const baseNum = ipv4ToInt(base);
    if (ipNum === null || baseNum === null) return false;
    return (ipNum & mask) === (baseNum & mask);
  } catch {
    return false;
  }
}

function ipv4ToInt(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}
