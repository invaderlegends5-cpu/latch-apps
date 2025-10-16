-- AlterEnum
ALTER TYPE "public"."EventType" ADD VALUE 'USED_REFRESH_TOKEN_PURGE';

-- CreateTable
CREATE TABLE "public"."EventLog" (
    "id" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "userId" TEXT,
    "tenantId" TEXT,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "integrityHash" VARCHAR(128) NOT NULL,
    "prevHash" VARCHAR(128),

    CONSTRAINT "EventLog_pkey" PRIMARY KEY ("id")
);
