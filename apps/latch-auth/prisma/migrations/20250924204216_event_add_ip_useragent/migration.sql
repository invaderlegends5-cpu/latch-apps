/*
  Warnings:

  - Changed the type of `type` on the `Event` table. No cast exists, the column would be dropped and recreated, which cannot be done if there is data, since the column is required.

*/
-- CreateEnum
CREATE TYPE "public"."EventType" AS ENUM ('LOGIN', 'LOGOUT', 'OTP_REQUEST', 'REFRESH_SUCCESS', 'REFRESH_FAILED', 'TOKEN_REUSE', 'SESSION_REVOKE', 'SESSION_REVOKE_ALL', 'SESSION_EXPIRED');

-- AlterTable
ALTER TABLE "public"."Event" ADD COLUMN     "ipAddress" TEXT,
ADD COLUMN     "userAgent" TEXT,
DROP COLUMN "type",
ADD COLUMN     "type" "public"."EventType" NOT NULL;

-- CreateIndex
CREATE INDEX "Event_createdAt_idx" ON "public"."Event"("createdAt");

-- CreateIndex
CREATE INDEX "Event_type_idx" ON "public"."Event"("type");
