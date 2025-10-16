-- DropForeignKey
ALTER TABLE "public"."RefreshToken" DROP CONSTRAINT "RefreshToken_sessionId_fkey";

-- CreateTable
CREATE TABLE "public"."UsedRefreshToken" (
    "id" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "usedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "sessionId" TEXT,
    "userId" TEXT,
    "refreshTokenId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "UsedRefreshToken_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "UsedRefreshToken_tokenHash_key" ON "public"."UsedRefreshToken"("tokenHash");

-- CreateIndex
CREATE INDEX "UsedRefreshToken_usedAt_idx" ON "public"."UsedRefreshToken"("usedAt");

-- CreateIndex
CREATE INDEX "UsedRefreshToken_userId_idx" ON "public"."UsedRefreshToken"("userId");

-- CreateIndex
CREATE INDEX "UsedRefreshToken_tokenHash_idx" ON "public"."UsedRefreshToken"("tokenHash");

-- CreateIndex
CREATE INDEX "UsedRefreshToken_refreshTokenId_idx" ON "public"."UsedRefreshToken"("refreshTokenId");

-- AddForeignKey
ALTER TABLE "public"."RefreshToken" ADD CONSTRAINT "RefreshToken_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "public"."Session"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."UsedRefreshToken" ADD CONSTRAINT "UsedRefreshToken_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "public"."Session"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."UsedRefreshToken" ADD CONSTRAINT "UsedRefreshToken_userId_fkey" FOREIGN KEY ("userId") REFERENCES "public"."User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."UsedRefreshToken" ADD CONSTRAINT "UsedRefreshToken_refreshTokenId_fkey" FOREIGN KEY ("refreshTokenId") REFERENCES "public"."RefreshToken"("id") ON DELETE SET NULL ON UPDATE CASCADE;
