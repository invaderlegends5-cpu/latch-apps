-- AlterTable
ALTER TABLE "public"."Role" ADD COLUMN     "description" TEXT,
ADD COLUMN     "isSystem" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "privileges" TEXT[] DEFAULT ARRAY[]::TEXT[];
