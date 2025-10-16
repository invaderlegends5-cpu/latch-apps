/*
  Warnings:

  - You are about to drop the `EventLog` table. If the table is not empty, all the data it contains will be lost.
  - Added the required column `integrityHash` to the `Event` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "public"."Event" ADD COLUMN     "integrityHash" VARCHAR(128) NOT NULL,
ADD COLUMN     "prevHash" VARCHAR(128);

-- DropTable
DROP TABLE "public"."EventLog";
