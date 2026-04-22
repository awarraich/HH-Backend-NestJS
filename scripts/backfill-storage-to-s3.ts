/**
 * One-off backfill: upload every file under ./storage/ to S3 using the same
 * relative path as the S3 key. DB values are already stored as relative paths
 * (e.g. "hr-documents/<orgId>/<empId>/<uuid>.pdf"), so after this script runs
 * against the same bucket the new pre-signed GET endpoints find the files.
 *
 * Usage (from HH-Backend-NestJS/):
 *   # Dry run — lists what would be uploaded, no writes
 *   ts-node -r tsconfig-paths/register scripts/backfill-storage-to-s3.ts
 *
 *   # Actually upload
 *   ts-node -r tsconfig-paths/register scripts/backfill-storage-to-s3.ts --commit
 *
 * Env required: AWS_REGION, S3_BUCKET_NAME, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
 * (from .env.local or environment).
 *
 * Re-runnable: skips files already present in S3 (HeadObject check).
 */

import 'dotenv/config';
import * as fs from 'fs';
import * as path from 'path';
import {
  S3Client,
  PutObjectCommand,
  HeadObjectCommand,
} from '@aws-sdk/client-s3';

const STORAGE_ROOT = process.env.STORAGE_PATH || './storage';
const BUCKET = process.env.S3_BUCKET_NAME;
const REGION = process.env.AWS_REGION || 'us-east-1';
const ACCESS_KEY = process.env.AWS_ACCESS_KEY_ID;
const SECRET_KEY = process.env.AWS_SECRET_ACCESS_KEY;
const COMMIT = process.argv.includes('--commit');

function guessContentType(filename: string): string {
  const ext = path.extname(filename).toLowerCase();
  const map: Record<string, string> = {
    '.pdf': 'application/pdf',
    '.doc': 'application/msword',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.xls': 'application/vnd.ms-excel',
    '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    '.txt': 'text/plain',
    '.csv': 'text/csv',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.gif': 'image/gif',
    '.webp': 'image/webp',
    '.svg': 'image/svg+xml',
    '.mp4': 'video/mp4',
    '.webm': 'video/webm',
    '.mov': 'video/quicktime',
  };
  return map[ext] ?? 'application/octet-stream';
}

function walk(dir: string, acc: string[] = []): string[] {
  if (!fs.existsSync(dir)) return acc;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, acc);
    else if (entry.isFile()) acc.push(full);
  }
  return acc;
}

async function main(): Promise<void> {
  if (!BUCKET) {
    console.error('ERROR: S3_BUCKET_NAME env var is required.');
    process.exit(1);
  }
  if (!fs.existsSync(STORAGE_ROOT)) {
    console.log(`Storage root ${STORAGE_ROOT} does not exist — nothing to backfill.`);
    return;
  }

  const client = new S3Client({
    region: REGION,
    credentials:
      ACCESS_KEY && SECRET_KEY
        ? { accessKeyId: ACCESS_KEY, secretAccessKey: SECRET_KEY }
        : undefined,
  });

  const files = walk(STORAGE_ROOT);
  console.log(
    `Found ${files.length} file(s) under ${STORAGE_ROOT}. Mode: ${COMMIT ? 'COMMIT' : 'DRY RUN'}.`,
  );

  let uploaded = 0;
  let skipped = 0;
  let failed = 0;

  for (const filePath of files) {
    const rel = path.relative(STORAGE_ROOT, filePath).split(path.sep).join('/');
    const key = rel;

    if (!COMMIT) {
      console.log(`[dry-run] ${filePath} -> s3://${BUCKET}/${key}`);
      continue;
    }

    try {
      try {
        await client.send(new HeadObjectCommand({ Bucket: BUCKET, Key: key }));
        console.log(`[skip]   ${key} (already in S3)`);
        skipped++;
        continue;
      } catch {
        // Not in S3 yet — proceed to upload
      }

      const buffer = fs.readFileSync(filePath);
      await client.send(
        new PutObjectCommand({
          Bucket: BUCKET,
          Key: key,
          Body: buffer,
          ContentType: guessContentType(filePath),
        }),
      );
      console.log(`[upload] ${key} (${buffer.length} bytes)`);
      uploaded++;
    } catch (err) {
      console.error(`[error]  ${key}: ${err instanceof Error ? err.message : String(err)}`);
      failed++;
    }
  }

  console.log('');
  console.log(`Done. uploaded=${uploaded}, skipped=${skipped}, failed=${failed}.`);
  if (!COMMIT) {
    console.log('(Dry run — re-run with --commit to actually upload.)');
  }
}

main().catch((err) => {
  console.error('Backfill failed:', err);
  process.exit(1);
});
