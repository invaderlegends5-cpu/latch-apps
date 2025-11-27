/*
  Warnings:

  - Added the required column `validUntil` to the `UserRole` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "UserRole" ADD COLUMN     "validUntil" TIMESTAMP(3) NOT NULL,
ALTER COLUMN "validFrom" DROP DEFAULT;
