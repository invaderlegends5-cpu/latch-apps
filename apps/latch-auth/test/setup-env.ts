import * as dotenv from 'dotenv';

// Load test environment variables for ALL e2e tests
dotenv.config({ path: '.env.test' });

// Set a default if not set
if (!process.env.DATABASE_URL) {
  process.env.DATABASE_URL = 'postgresql://latch:latch123@localhost:5432/latch_auth';
}

// Increase timeout for all hooks
jest.setTimeout(30000);