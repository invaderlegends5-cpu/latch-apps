/**
 * prisma/seed-check.ts
 * ---------------------------------------
 * Simple verification helper to confirm mock seed data was created.
 * Run manually via:
 *   bun run seed:check
 * or automatically in CI (as we do in test-latch-auth.yml).
 */

import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  console.log('🔍 Verifying mock seed presence...');

  const tenantCount = await prisma.tenant.count();
  const userCount = await prisma.user.count();
  const sessionCount = await prisma.session.count();

  console.log(`Tenants: ${tenantCount}, Users: ${userCount}, Sessions: ${sessionCount}`);

  if (tenantCount === 0) {
    console.error('❌ No tenants found — seed likely failed.');
    process.exit(1);
  }

  if (userCount === 0) {
    console.warn('⚠️ No users found — incomplete seed, continuing anyway.');
  }

  console.log('✅ Mock seed verification passed.');
}

main()
  .catch((err) => {
    console.error('❌ Seed verification failed:', err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
