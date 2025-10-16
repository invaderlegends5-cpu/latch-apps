-- AlterTable
ALTER TABLE "public"."Session" ADD COLUMN     "revoked" BOOLEAN NOT NULL DEFAULT false;

-- CreateTable
CREATE TABLE "public"."Event" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "tenantId" TEXT,
    "type" TEXT NOT NULL,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Event_pkey" PRIMARY KEY ("id")
);
