-- CreateTable
CREATE TABLE "IPBlock" (
    "id" TEXT NOT NULL,
    "ip" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "blockedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "IPBlock_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IPWhitelist" (
    "id" TEXT NOT NULL,
    "ip" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "addedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "addedBy" TEXT,

    CONSTRAINT "IPWhitelist_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IPReputationHistory" (
    "id" TEXT NOT NULL,
    "ip" TEXT NOT NULL,
    "score" INTEGER NOT NULL,
    "riskLevel" TEXT NOT NULL,
    "eventCounts" JSONB,
    "recordedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "source" TEXT NOT NULL,

    CONSTRAINT "IPReputationHistory_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "IPBlock_expiresAt_idx" ON "IPBlock"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "IPBlock_ip_key" ON "IPBlock"("ip");

-- CreateIndex
CREATE INDEX "IPWhitelist_addedAt_idx" ON "IPWhitelist"("addedAt");

-- CreateIndex
CREATE UNIQUE INDEX "IPWhitelist_ip_key" ON "IPWhitelist"("ip");

-- CreateIndex
CREATE INDEX "IPReputationHistory_ip_recordedAt_idx" ON "IPReputationHistory"("ip", "recordedAt");

-- CreateIndex
CREATE INDEX "IPReputationHistory_recordedAt_idx" ON "IPReputationHistory"("recordedAt");
