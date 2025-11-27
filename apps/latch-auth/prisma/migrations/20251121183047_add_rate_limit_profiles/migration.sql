-- AlterTable
ALTER TABLE "TenantPolicy" ADD COLUMN     "customRateLimitProfileId" TEXT;

-- CreateTable
CREATE TABLE "TenantRateLimitProfile" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "limits" JSONB NOT NULL,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "isDefault" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "TenantRateLimitProfile_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "TenantRateLimitProfile_tenantId_key" ON "TenantRateLimitProfile"("tenantId");

-- CreateIndex
CREATE INDEX "TenantRateLimitProfile_tenantId_idx" ON "TenantRateLimitProfile"("tenantId");

-- CreateIndex
CREATE INDEX "TenantRateLimitProfile_isActive_idx" ON "TenantRateLimitProfile"("isActive");

-- CreateIndex
CREATE INDEX "TenantRateLimitProfile_isDefault_idx" ON "TenantRateLimitProfile"("isDefault");

-- AddForeignKey
ALTER TABLE "TenantPolicy" ADD CONSTRAINT "TenantPolicy_customRateLimitProfileId_fkey" FOREIGN KEY ("customRateLimitProfileId") REFERENCES "TenantRateLimitProfile"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TenantRateLimitProfile" ADD CONSTRAINT "TenantRateLimitProfile_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
