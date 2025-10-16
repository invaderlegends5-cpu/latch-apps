-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "public"."EventType" ADD VALUE 'ROLE_ACCESS_DENIED';
ALTER TYPE "public"."EventType" ADD VALUE 'ROLE_ACCESS_GRANTED';
ALTER TYPE "public"."EventType" ADD VALUE 'PRIVILEGE_ACCESS_DENIED';
ALTER TYPE "public"."EventType" ADD VALUE 'PRIVILEGE_ACCESS_GRANTED';
