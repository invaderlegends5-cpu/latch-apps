import { EventType } from '../../events/event.types';

export interface IPReputationScore {
  ip: string;
  score: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  totalEvents: number;
  securityEvents: number;
  lastUpdated: Date;
  eventCounts: Record<EventType, number>;
  threatIndicators: ThreatIndicator[];
  reputationHistory: ReputationSnapshot[];
  blocked: boolean;
  blockReason?: string;
  blockUntil?: Date;
  whitelisted: boolean;
  metadata: Record<string, any>;
}

export interface ThreatIndicator {
  type: 'BRUTE_FORCE' | 'DDOS' | 'MALICIOUS_ACTIVITY' | 'ANOMALY' | 'GEO_RISK';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  evidence: string;
  timestamp: Date;
  scoreImpact: number;
}

export interface ReputationSnapshot {
  timestamp: Date;
  score: number;
  eventCounts: Record<EventType, number>;
  riskLevel: IPReputationScore['riskLevel'];
}

export interface IPReputationConfig {
  scoring: {
    weights: Record<EventType, number>;
    decayRate: number;
    maxScore: number;
    minScore: number;
  };
  blocking: {
    thresholds: {
      medium: number;
      high: number;
      critical: number;
    };
    autoBlock: boolean;
    blockDuration: number;
    maxBlockDuration: number;
  };
  monitoring: {
    anomalyDetection: boolean;
    geoRiskAnalysis: boolean;
    behavioralAnalysis: boolean;
  };
  retention: {
    historyDays: number;
    threatIndicatorsDays: number;
  };
}

export interface ReputationQueryOptions {
  includeHistory?: boolean;
  includeThreats?: boolean;
  daysBack?: number;
  minScore?: number;
  maxScore?: number;
  riskLevel?: IPReputationScore['riskLevel'][];
  blockedOnly?: boolean;
}

export interface ReputationUpdateResult {
  ip: string;
  previousScore: number;
  newScore: number;
  riskLevelChanged: boolean;
  actionTaken: 'NONE' | 'BLOCKED' | 'UNBLOCKED' | 'ALERTED';
  reason?: string;
}