// test/jest-e2e.setup.ts
import { PrismaClient } from '@prisma/client';

// Ensure clean DB disconnection after all tests
afterAll(async () => {
  const prisma = new PrismaClient();
  await prisma.$disconnect();
});