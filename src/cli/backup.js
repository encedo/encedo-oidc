#!/usr/bin/env node
/**
 * Redis logical backup -- SCAN + DUMP/PTTL -> gzipped NDJSON.
 *
 *   npm run backup                          # -> ./backups/redis-backup-<ts>.ndjson.gz
 *   npm run backup -- --out /var/backups
 *   npm run backup -- --file -              # stream to stdout (pipe to gpg/age/ssh)
 *   npm run backup -- --skip-ephemeral      # drop pending:/code:/enroll_lock:/rl:
 *   npm run backup -- --match 'user:*'      # partial backup
 *   npm run backup -- --no-gzip
 *
 * Why DUMP rather than per-type reads: the payload is RDB-serialised, so RESTORE
 * rebuilds every type (hash, set, zset, string) and its TTL exactly, and the
 * format survives schema changes without touching this file.
 *
 * The payloads are BINARY. node-redis decodes replies as UTF-8 by default, which
 * silently corrupts them -- hence commandOptions({ returnBuffers: true }).
 *
 * SECURITY: the output contains client secrets, access tokens, HSM certs and
 * public keys. Files are written 0600. Store them encrypted.
 */
import 'dotenv/config';
import { commandOptions } from 'redis';
import { createWriteStream } from 'fs';
import { mkdir, rename, chmod, stat, unlink } from 'fs/promises';
import { createGzip } from 'zlib';
import { pipeline } from 'stream/promises';
import { Readable } from 'stream';
import { resolve, join, dirname } from 'path';
import {
  parseArgs, connect, redactUrl, redisVersion, die, humanSize,
  DEFAULT_URL, FORMAT, FORMAT_VER, EPHEMERAL,
} from './common.js';

const SCAN_COUNT = 500;

const args = parseArgs(process.argv.slice(2));

if (args.help || args.h) {
  console.log(`Usage: npm run backup -- [options]

  --url <redis-url>   default: $REDIS_URL or redis://127.0.0.1:6379
  --out <dir>         output directory (default: ./backups)
  --file <path|->     exact output path; "-" streams to stdout
  --match <glob>      only back up keys matching this pattern (default: *)
  --skip-ephemeral    skip pending:/code:/enroll_lock:/rl: keys
  --no-gzip           write plain NDJSON
  --quiet             suppress the summary`);
  process.exit(0);
}

const url           = args.url ?? DEFAULT_URL;
const match         = args.match ?? '*';
const useGzip       = !args['no-gzip'];
const skipEphemeral = Boolean(args['skip-ephemeral']);
const toStdout      = args.file === '-';
const quiet         = Boolean(args.quiet);

// Always log to stderr, never stdout -- stdout may carry the backup itself
// (--file -). Piping the data away must still show the summary.
const log = (...m) => { if (!quiet) console.error(...m); };

const stamp   = new Date().toISOString().replace(/[:.]/g, '-');
const ext     = useGzip ? '.ndjson.gz' : '.ndjson';
const outPath = toStdout
  ? null
  : resolve(args.file ?? join(args.out ?? 'backups', `redis-backup-${stamp}${ext}`));

const client  = await connect(url);
const version = await redisVersion(client);
const dbsize  = await client.dbSize();

const counters = { keys: 0, ephemeral: 0, vanished: 0 };

/** Streams the backup as NDJSON: header line, one line per key, end marker. */
async function* lines() {
  yield JSON.stringify({
    format:       FORMAT,
    version:      FORMAT_VER,
    createdAt:    new Date().toISOString(),
    source:       redactUrl(url),          // credentials stripped
    redisVersion: version,
    dbsize,
    match,
    skipEphemeral,
  }) + '\n';

  let cursor = 0;
  do {
    const res = await client.scan(cursor, { MATCH: match, COUNT: SCAN_COUNT });
    cursor = res.cursor;                   // v4: number, v5: string -- compared as string below

    let keys = res.keys;
    if (skipEphemeral) {
      const before = keys.length;
      keys = keys.filter((k) => !EPHEMERAL.some((re) => re.test(k)));
      counters.ephemeral += before - keys.length;
    }
    if (keys.length === 0) continue;

    // Issued in one tick -> node-redis pipelines them into a single round trip.
    const [dumps, ttls] = await Promise.all([
      Promise.all(keys.map((k) => client.dump(commandOptions({ returnBuffers: true }), k))),
      Promise.all(keys.map((k) => client.pTTL(k))),
    ]);

    for (let i = 0; i < keys.length; i++) {
      const payload = dumps[i];
      if (payload == null) { counters.vanished++; continue; }  // expired between SCAN and DUMP

      counters.keys++;
      yield JSON.stringify({
        k: keys[i],
        t: ttls[i] < 0 ? -1 : ttls[i],     // -1 = no expiry; -2 (gone) can't reach here
        v: payload.toString('base64'),
      }) + '\n';
    }
  } while (String(cursor) !== '0');

  // End marker -- restore refuses a file without it, so a truncated backup
  // can never be mistaken for a complete one.
  yield JSON.stringify({ _end: true, keys: counters.keys }) + '\n';
}

const tmpPath = outPath ? `${outPath}.part` : null;

try {
  if (outPath) await mkdir(dirname(outPath), { recursive: true });

  const source = Readable.from(lines());
  const sink   = toStdout ? process.stdout : createWriteStream(tmpPath, { mode: 0o600 });
  const stages = useGzip ? [source, createGzip(), sink] : [source, sink];

  await pipeline(...stages);

  if (outPath) {
    // Publish atomically: a crash mid-write leaves only the .part file behind.
    await rename(tmpPath, outPath);
    await chmod(outPath, 0o600);
  }
} catch (err) {
  if (tmpPath) await unlink(tmpPath).catch(() => {});
  await client.quit().catch(() => {});
  die(`backup failed: ${err.message}`);
}

await client.quit();

const skipped = [
  counters.ephemeral ? `${counters.ephemeral} ephemeral` : null,
  counters.vanished  ? `${counters.vanished} expired mid-scan` : null,
].filter(Boolean).join(', ');

log(`[backup] source  ${redactUrl(url)} (redis ${version}, ${dbsize} keys)`);
log(`[backup] saved   ${counters.keys} keys${skipped ? ` (skipped ${skipped})` : ''}`);
if (outPath) {
  const { size } = await stat(outPath);
  log(`[backup] output  ${outPath} (${humanSize(size)}, mode 0600)`);
  log('[backup] NOTE: contains client secrets and access tokens -- store encrypted.');
}
