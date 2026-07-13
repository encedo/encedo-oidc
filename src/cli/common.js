/**
 * Shared helpers for the CLI commands (backup / restore).
 *
 * Deliberately does NOT reuse src/services/redis.js: that module is the app
 * singleton -- it connects on import and retries forever. A CLI wants the
 * opposite: one shot, fail fast, explicit quit. A silent reconnect loop in the
 * middle of a backup would produce a truncated file that still looks valid.
 */
import { createClient } from 'redis';

export const DEFAULT_URL = process.env.REDIS_URL ?? 'redis://127.0.0.1:6379';

/** Minimal parser for `--flag value`, `--flag=value` and boolean `--flag`. */
export function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) { out._.push(arg); continue; }

    const eq = arg.indexOf('=');
    if (eq !== -1)                                     out[arg.slice(2, eq)] = arg.slice(eq + 1);
    else if (argv[i + 1] && !argv[i + 1].startsWith('--')) out[arg.slice(2)] = argv[++i];
    else                                               out[arg.slice(2)] = true;
  }
  return out;
}

/** Strip credentials -- the URL gets printed and stored in the backup header. */
export function redactUrl(url) {
  try {
    const u = new URL(url);
    if (u.password) u.password = '***';
    if (u.username) u.username = '***';
    return u.toString();
  } catch {
    return 'redis://<unparseable>';
  }
}

/**
 * One-shot client: no reconnect loop, short connect timeout.
 * A dropped connection must fail loudly rather than silently truncate a backup.
 */
export async function connect(url) {
  const client = createClient({
    url,
    socket: { connectTimeout: 5000, reconnectStrategy: false },
  });

  // node-redis emits 'error' on the client; without a listener Node crashes with
  // an unhandled 'error' event. Real failures still surface at the awaited command.
  let lastError = null;
  client.on('error', (err) => { lastError = err; });

  try {
    await client.connect();
  } catch (err) {
    die(`cannot connect to ${redactUrl(url)}: ${(lastError ?? err).message}`);
  }
  return client;
}

/** redis_version from INFO -- recorded in the header (RESTORE is RDB-version sensitive). */
export async function redisVersion(client) {
  try {
    const info = await client.info('server');
    return /redis_version:([^\r\n]+)/.exec(info)?.[1] ?? 'unknown';
  } catch {
    return 'unknown';
  }
}

export function die(msg) {
  console.error(`error: ${msg}`);
  process.exit(1);
}

/** Human-readable byte size for the summary line. */
export function humanSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB'];
  let value = bytes / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) { value /= 1024; i++; }
  return `${value.toFixed(1)} ${units[i]}`;
}

export const FORMAT     = 'encedo-oidc-redis-backup';
export const FORMAT_VER = 1;

/**
 * Keys not worth carrying into a backup: in-flight auth state that expires in
 * seconds (see the Redis schema in CLAUDE.md). Opt in with --skip-ephemeral.
 *   pending:{sid}     120s login session
 *   code:{code}        60s authorization code
 *   enroll_lock:{sub}  30s NX lock
 *   rl:{prefix}:{id}   rate-limit counters
 */
export const EPHEMERAL = [/^pending:/, /^code:/, /^enroll_lock:/, /^rl:/];
