-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "public"."EventType" ADD VALUE 'SECURITY_CSRF_ERROR';
ALTER TYPE "public"."EventType" ADD VALUE 'SECURITY_CSRF_MISMATCH';
ALTER TYPE "public"."EventType" ADD VALUE 'AUTH_JWT_FAILURE';
ALTER TYPE "public"."EventType" ADD VALUE 'TENANT_VALIDATION_ERROR';
ALTER TYPE "public"."EventType" ADD VALUE 'TENANT_MISMATCH';
ALTER TYPE "public"."EventType" ADD VALUE 'USER_DATA_ACCESS_ATTEMPT';
ALTER TYPE "public"."EventType" ADD VALUE 'USER_DATA_ACCESSED';
ALTER TYPE "public"."EventType" ADD VALUE 'USER_LIST_ACCESSED';
ALTER TYPE "public"."EventType" ADD VALUE 'USER_LIST_ACCESS_DENIED';
ALTER TYPE "public"."EventType" ADD VALUE 'USER_PROFILE_UPDATE';
ALTER TYPE "public"."EventType" ADD VALUE 'USER_PROFILE_UPDATE_FAILED';
ALTER TYPE "public"."EventType" ADD VALUE 'SENSITIVE_DATA_ACCESSED';
ALTER TYPE "public"."EventType" ADD VALUE 'AUDIT_TRAIL_ACCESS_DENIED';
ALTER TYPE "public"."EventType" ADD VALUE 'AUDIT_TRAIL_ACCESS_ATTEMPTED';
ALTER TYPE "public"."EventType" ADD VALUE 'AUDIT_TRAIL_ACCESSED';
ALTER TYPE "public"."EventType" ADD VALUE 'DATA_EXPORT_ATTEMPTED';
ALTER TYPE "public"."EventType" ADD VALUE 'DATA_EXPORT_ATTEMPT_DENIED';
ALTER TYPE "public"."EventType" ADD VALUE 'DATA_EXPORT_INITIATED';
ALTER TYPE "public"."EventType" ADD VALUE 'DATA_EXPORTED';
ALTER TYPE "public"."EventType" ADD VALUE 'SECURITY_STATUS_CHECKED';
ALTER TYPE "public"."EventType" ADD VALUE 'AUTHENTICATION_VERIFICATION_FAILED';
ALTER TYPE "public"."EventType" ADD VALUE 'AUTHENTICATION_VERIFIED';

-- DropIndex
DROP INDEX "public"."Event_createdAt_idx";

-- DropIndex
DROP INDEX "public"."Event_type_idx";

-- CreateIndex
CREATE INDEX "Event_type_createdAt_idx" ON "public"."Event"("type", "createdAt");
