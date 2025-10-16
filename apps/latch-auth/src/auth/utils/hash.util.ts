// src/auth/utils/hash.util.ts
import * as crypto from 'crypto';

export function hashToken(token: string) {
  return crypto.createHash('sha256').update(token).digest('hex');
}
