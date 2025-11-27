// src/auth/utils/hash.util.ts
import * as crypto from 'crypto';

export function hashToken(token: string) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

export function generateIntegrityHash(data: string, secret?: string): string {
  const hashSecret = secret || process.env.AUDIT_HASH_SECRET || 'fallback-secret-key';
  return crypto
    .createHmac('sha256', hashSecret)
    .update(data)
    .digest('hex');
}