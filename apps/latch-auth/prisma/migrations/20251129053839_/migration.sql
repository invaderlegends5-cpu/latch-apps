/*
  Warnings:

  - A unique constraint covering the columns `[tenantId,name]` on the table `TenantRateLimitProfile` will be added. If there are existing duplicate values, this will fail.

*/
-- DropIndex
DROP INDEX "public"."TenantRateLimitProfile_tenantId_key";

-- CreateIndex
CREATE UNIQUE INDEX "TenantRateLimitProfile_tenantId_name_key" ON "TenantRateLimitProfile"("tenantId", "name");
