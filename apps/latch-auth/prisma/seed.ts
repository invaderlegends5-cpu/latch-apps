import { PrismaClient } from '@prisma/client';
// @ts-ignore
import * as crypto from 'crypto';

const prisma = new PrismaClient();

// --- Utility: stable sort (identical to EventLogService) ---
function sortObjectKeys(obj: any): any {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) return obj;
  return Object.keys(obj)
    .sort()
    .reduce((acc: any, k) => {
      acc[k] = sortObjectKeys(obj[k]);
      return acc;
    }, {});
}

// --- Utility: integrity hashing (identical to EventLogService) ---
function computeIntegrity(payload: Record<string, any>, secret: string): string {
  const stable = JSON.stringify(sortObjectKeys(payload));
  const toHash = `${stable}::${secret}`;
  return crypto.createHash('sha256').update(toHash).digest('hex');
}

// --- Optional helpers (mask/truncate, same as service) ---
function maskIp(ip?: string | null): string | null {
  if (!ip) return null;
  if (ip.includes(':')) {
    const parts = ip.split(':');
    const head = parts.slice(0, 4).join(':');
    return `${head}::`;
  }
  const parts = ip.split('.');
  if (parts.length === 4) {
    parts[3] = 'x';
    return parts.join('.');
  }
  return null;
}
function truncateUserAgent(ua?: string | null, max = 256): string | null {
  if (!ua) return null;
  return ua.length > max ? ua.substring(0, max) : ua;
}

async function main() {
  const tenantCount = await prisma.tenant.count();
  if (tenantCount > 0) {
    console.log('✅ Mock seed skipped — DB already populated.');
    return;
  }

  console.log('🌱 Seeding mock data...');

  // Create Tenant + User + Session
  const tenant = await prisma.tenant.create({
    data: { name: 'Demo Tenant', slug: 'demo' },
  });

  const user = await prisma.user.create({
    data: {
      tenantId: tenant.id,
      phone: '+15555550123',
      name: 'Demo User',
      isPhoneVerified: true,
    },
  });

  await prisma.session.create({
    data: {
      userId: user.id,
      tenantId: tenant.id,
      refreshHash: 'mock-refresh-hash',
      ipAddress: '127.0.0.1',
      userAgent: 'seed-script',
      lastActiveAt: new Date(),
      expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24),
    },
  });

  // --- Create a mock security event with integrity chain ---
  // Use Bun's environment variables: use globalThis.Bun?.env for compatibility and fallback
  const secret = (globalThis.Bun?.env?.EVENT_SIGNING_SECRET) ?? 'dev-secret';
  const last = await prisma.event.findFirst({
    orderBy: { createdAt: 'desc' },
    select: { integrityHash: true },
  });


  const prevHash = last?.integrityHash ?? null;

  const payload = {
    userId: user.id,
    tenantId: tenant.id,
    type: 'SECURITY_STATUS_CHECKED',
    severity: 'INFO',
    metadata: sortObjectKeys({ seeded: true }),
    ipAddress: maskIp('127.0.0.1'),
    userAgent: truncateUserAgent('seed-script'),
    prevHash,
    createdAt: new Date().toISOString(),
  };

  const integrityHash = computeIntegrity(payload, secret);

  await prisma.event.create({
    data: {
      userId: user.id,
      tenantId: tenant.id,
      type: 'SECURITY_STATUS_CHECKED',
      severity: 'INFO',
      metadata: payload.metadata,
      ipAddress: payload.ipAddress,
      userAgent: payload.userAgent,
      integrityHash,
      prevHash,
    },
  });

  console.log('🧩 Mock security event logged.');
  console.log('✅ Mock seed completed.');
}

main()
  .catch((e) => {
    console.error('❌ Mock seed failed:', e);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
