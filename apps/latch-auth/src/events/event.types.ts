// src/events/event.types.ts
import { $Enums } from '@prisma/client';

export type EventType = $Enums.EventType;
export type EventSeverity = $Enums.EventSeverity;

export interface EventMeta {
  sessionId?: string;
  familyId?: string;
  reason?: string;
  tokenId?: string;
  csrfTokenRotated?: boolean;
  [key: string]: any;
}

export interface SecurityEvent {
  id: string;
  type: EventType;
  severity: EventSeverity;
  userId: string | null;
  tenantId: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  sessionId: string | null;
  familyId: string | null;
  reason: string | null;
  integrityHash: string;
  prevHash: string | null;
  metadata: EventMeta;
  createdAt: Date;
}

export type ChainVerificationValid = {
  valid: true;
  total: number;
};

export type ChainVerificationBroken = {
  valid: false;
  brokenIndex: number;
  total: number;
};

export type ChainVerificationErrored = {
  valid: false;
  error: string;
};

export type ChainVerificationResult =
  | ChainVerificationValid
  | ChainVerificationBroken
  | ChainVerificationErrored;
