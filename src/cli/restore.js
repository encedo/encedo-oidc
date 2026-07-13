#!/usr/bin/env node
/**
 * Restore a backup produced by src/cli/backup.js.
 *
 *   npm run restore -- ./backups/redis-backup-<ts>.ndjson.gz --dry-run
 *   npm run restore -- ./backups/redis-backup-<ts>.ndjson.gz --replace
 *   npm run restore -- ./backups/redis-backup-<ts>.ndjson.gz --flush --yes
 *
 * Safety rules:
 *   - the file is fully validated BEFORE a single key is written (a truncated
 *     backup must not leave the database half-restored);
 *   - a non-empty target is refused unless --replace (merge) or --flush --yes (wipe);
 *   - --flush additionally requires --yes, because it destroys the live database.
 *
 * TTLs are restored relative to the moment of restore (RESTORE without ABSTTL),
 * so a key that had 10h left when dumped gets 10h from now.
 */
import 'dotenv/config';
import { createReadStream } from 'fs';
import { open } from 'fs/promises';
import { createGunzip } from 'zlib';
import { createInterface } from 'readline';
import { resolve } from 'path';
import {
  parseArgs, connect, redactUrl, redisVersion, die,
  DEFAULT_URL, FORMAT, FORMAT_VER,
} from './common.js';

const BATCH = 200;

const args = parseArgs(process.argv.slice(2));

if (args.help || args.h || args._.length === 0) {
  console.log(`Usage: npm run restore -- <backup-file> [options]

  --url <redis-url>   default: $REDIS_URL or redis://127.0.0.1:6379
  --dry-run           validate the file and report, write nothing
  --replace           overwrite keys that already exist (merge into target)
  --flush --yes       FLUSHDB the target first (destroys the live database)`);
  process.exit(args._.length === 0 ? 1 : 0);
}

const file    = resolve(args._[0]);
const url     = args.url ?? DEFAULT_URL;
const dryRun  = Boolean(args['dry-run']);
const replace = Boolean(args.replace);
const flush   = Boolean(args.flush);

if (flush && !args.yes) die('--flush wipes the target database; add --yes to confirm');

/** Detect gzip by magic bytes rather than by file extension. */
async function isGzip(path) {
  let fh;
  try {
    fh = await open(path, 'r');
  } catch (err) {
    die(`cannot read ${path}: ${err.message}`);
  }
  try {
    const buf = Buffer.alloc(2);
    const { bytesRead } = await fh.read(buf, 0, 2, 0);
    return bytesRead === 2 && buf[0] === 0x1f && buf[1] === 0x8b;
  } finally {
    await fh.close();
  }
}

const gzipped = await isGzip(file);

/** Streams the backup, invoking onEntry for each key. Returns the parsed header. */
async function readBackup(onEntry) {
  const raw    = createReadStream(file);
  const stream = gzipped ? raw.pipe(createGunzip()) : raw;
  const rl     = createInterface({ input: stream, crlfDelay: Infinity });

  let header = null;
  let end    = null;
  let lineNo = 0;

  for await (const line of rl) {
    lineNo++;
    if (!line.trim()) continue;

    let obj;
    try {
      obj = JSON.parse(line);
    } catch {
      die(`${file}:${lineNo} is not valid JSON -- file is corrupt`);
    }

    if (lineNo === 1) {
      if (obj.format !== FORMAT)       die(`not an ${FORMAT} file (found format: ${obj.format ?? 'none'})`);
      if (obj.version !== FORMAT_VER)  die(`unsupported backup version ${obj.version} (this tool reads v${FORMAT_VER})`);
      header = obj;
      continue;
    }

    if (obj._end) { end = obj; continue; }
    if (end)      die(`${file}:${lineNo} has data after the end marker -- file is corrupt`);

    if (typeof obj.k !== 'string' || typeof obj.v !== 'string' || typeof obj.t !== 'number') {
      die(`${file}:${lineNo} is malformed (expected {k,t,v})`);
    }
    await onEntry(obj);
  }

  if (!header) die(`${file} is empty`);
  if (!end)    die(`${file} is truncated (no end marker) -- refusing to restore a partial backup`);
  return { header, end };
}

// --- Pass 1: validate the whole file before touching Redis ---------------------
let counted = 0;
const { header, end } = await readBackup((entry) => {
  // Buffer.from is lenient with bad base64, so verify the payload round-trips.
  const buf = Buffer.from(entry.v, 'base64');
  if (buf.length === 0 || buf.toString('base64').replace(/=+$/, '') !== entry.v.replace(/=+$/, '')) {
    die(`key "${entry.k}" has a corrupt payload`);
  }
  counted++;
});

if (counted !== end.keys) {
  die(`file claims ${end.keys} keys but contains ${counted} -- refusing to restore`);
}

console.error(`[restore] file    ${file}${gzipped ? ' (gzip)' : ''}`);
console.error(`[restore] created ${header.createdAt} from ${header.source} (redis ${header.redisVersion})`);
console.error(`[restore] keys    ${counted} -- file validated`);

if (dryRun) {
  console.error('[restore] dry run -- nothing written');
  process.exit(0);
}

// --- Pass 2: write ------------------------------------------------------------
const client = await connect(url);
const target = await redisVersion(client);
const dbsize = await client.dbSize();

if (dbsize > 0 && !replace && !flush) {
  await client.quit().catch(() => {});
  die(`target ${redactUrl(url)} is not empty (${dbsize} keys).\n`
    + '       Re-run with --replace (overwrite colliding keys) or --flush --yes (wipe first).');
}

console.error(`[restore] target  ${redactUrl(url)} (redis ${target}, ${dbsize} keys)`);

if (flush) {
  await client.flushDb();
  console.error(`[restore] flushed ${dbsize} keys from target`);
}

const failures = [];
let restored = 0;
let batch    = [];

async function writeBatch() {
  if (batch.length === 0) return;

  const results = await Promise.allSettled(batch.map((e) =>
    client.restore(
      e.k,
      e.t < 0 ? 0 : e.t,                        // 0 = no expiry
      Buffer.from(e.v, 'base64'),
      replace ? { REPLACE: true } : {},
    ),
  ));

  results.forEach((r, i) => {
    if (r.status === 'fulfilled') restored++;
    else failures.push({ key: batch[i].k, message: r.reason.message });
  });
  batch = [];
}

await readBackup(async (entry) => {
  batch.push(entry);
  if (batch.length >= BATCH) await writeBatch();
});
await writeBatch();

await client.quit();

console.error(`[restore] wrote   ${restored}/${counted} keys`);

if (failures.length > 0) {
  const busy = failures.filter((f) => f.message.includes('BUSYKEY')).length;
  console.error(`[restore] FAILED  ${failures.length} keys`);
  for (const f of failures.slice(0, 10)) console.error(`            ${f.key}: ${f.message}`);
  if (failures.length > 10) console.error(`            ... and ${failures.length - 10} more`);
  if (busy > 0) console.error('[restore] hint: keys already exist -- re-run with --replace to overwrite them.');
  if (failures.some((f) => /checksum|payload version/i.test(f.message))) {
    console.error(`[restore] hint: RDB payload rejected -- the target redis (${target}) is older than the`);
    console.error(`            source (${header.redisVersion}). Restore into an equal or newer redis.`);
  }
  process.exit(1);
}
