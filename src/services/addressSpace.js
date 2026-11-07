/**
 * Address space of a host, as a Chromium browser sees it for Local Network
 * Access: a page on a public site that fetches a 'local' (private) or
 * 'loopback' address makes the browser ask the user first. The sign-in and
 * enrollment pages use this to tell the user what is about to happen when
 * their HEM (e.g. my.ence.do -> 192.168.7.1) sits on their own network.
 *
 * DNS only: the host is resolved, never contacted. The classification is a
 * superset of Chromium's (100.64/10 included): a needless notice costs a
 * modal, a missing one costs a user who does not know why nothing works.
 */
import { isIP } from 'node:net';
import { promises as dns } from 'node:dns';

function v4Space(ip) {
  const [a, b] = ip.split('.').map(Number);
  if (a === 127) return 'loopback';
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return 'local';
  if (a === 169 && b === 254) return 'local';             // link-local
  if (a === 100 && b >= 64 && b <= 127) return 'local';   // CGNAT, shared address space
  if (a === 0) return 'local';
  return 'public';
}

/** 'loopback' | 'local' | 'public' for one IP literal. */
export function ipSpace(ip) {
  const fam = isIP(ip);
  if (fam === 4) return v4Space(ip);
  if (fam !== 6) throw new Error(`not an IP address: ${ip}`);
  const s = ip.toLowerCase();
  const mapped = s.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return v4Space(mapped[1]);
  if (s === '::1') return 'loopback';
  if (/^f[cd]/.test(s)) return 'local';                    // fc00::/7 unique local
  if (/^fe[89ab]/.test(s)) return 'local';                 // fe80::/10 link-local
  if (s === '::') return 'local';
  return 'public';
}

const HOST_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.?$/i;

/** Validated host name or IP literal ('[::1]' unwrapped), or null. */
export function normalizeHost(host) {
  if (typeof host !== 'string') return null;
  const h = host.trim().replace(/^\[(.*)\]$/, '$1');
  if (isIP(h)) return h;
  return HOST_RE.test(h) ? h.toLowerCase() : null;
}

/**
 * { space: 'loopback' | 'local' | 'public' | 'unresolved', addresses }
 * The most private address wins: a browser that may connect to any of them
 * has to treat the host as that.
 */
export async function hostSpace(host, { timeoutMs = 3000 } = {}) {
  if (isIP(host)) return { space: ipSpace(host), addresses: [host] };
  let addrs;
  try {
    let t;
    addrs = await Promise.race([
      dns.lookup(host, { all: true, verbatim: true }),
      new Promise((_, rej) => { t = setTimeout(() => rej(new Error('timeout')), timeoutMs); }),
    ]).finally(() => clearTimeout(t));
  } catch {
    return { space: 'unresolved', addresses: [] };
  }
  const spaces = addrs.map(a => ipSpace(a.address));
  const space = spaces.includes('loopback') ? 'loopback' : spaces.includes('local') ? 'local' : 'public';
  return { space, addresses: addrs.map(a => a.address) };
}
