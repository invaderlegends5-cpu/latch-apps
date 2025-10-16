/*
  Warnings:

  - You are about to drop the column `adminMFARequired` on the `TenantPolicy` table. All the data in the column will be lost.
  - Added the required column `lastActiveAt` to the `Session` table without a default value. This is not possible if the table is not empty.

*/
-- CreateEnum
CREATE TYPE "public"."EventSeverity" AS ENUM ('INFO', 'SECURITY', 'ERROR');

-- AlterTable
ALTER TABLE "public"."Event" ADD COLUMN     "familyId" TEXT,
ADD COLUMN     "reason" TEXT,
ADD COLUMN     "sessionId" UUID,
ADD COLUMN     "severity" "public"."EventSeverity" NOT NULL DEFAULT 'INFO';

-- AlterTable
ALTER TABLE "public"."Session" ADD COLUMN     "lastActiveAt" TIMESTAMP(3) NOT NULL;

-- AlterTable
ALTER TABLE "public"."TenantPolicy" DROP COLUMN "adminMFARequired",
ADD COLUMN     "privilegedUserMFARequired" BOOLEAN NOT NULL DEFAULT true;

-- CreateIndex
CREATE INDEX "Event_sessionId_idx" ON "public"."Event"("sessionId");

-- CreateIndex
CREATE INDEX "Event_familyId_idx" ON "public"."Event"("familyId");

-- CreateIndex
CREATE INDEX "Event_reason_idx" ON "public"."Event"("reason");
