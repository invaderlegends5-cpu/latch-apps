import { EventType } from '../../events/event.types';

export interface RequestPattern {
  timestamp: Date;
  method: string;
  url: string;
  userAgent: string | null;
  ipAddress: string | null;
  sessionId: string | null;
  userId: string | null;
  responseTime: number;
  userAgentChange: boolean;
  ipChange: boolean;
}

export interface BehavioralSession {
  sessionId: string;
  userId: string;
  ipAddress: string;
  userAgent: string;
  firstRequest: Date;
  lastRequest: Date;
  totalRequests: number;
  requestIntervalStats: {
    mean: number;
    stdDev: number;
    min: number;
    max: number;
  };
  navigationSequence: string[];
  suspiciousIndicators: SuspiciousIndicator[];
  riskScore: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface SuspiciousIndicator {
  type: 'RATE_ANOMALY' | 'NAVIGATION_ANOMALY' | 'TIMING_ANOMALY' | 'USER_AGENT_ANOMALY' | 'IP_ANOMALY';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  evidence: string;
  timestamp: Date;
  scoreImpact: number;
}

export interface BehavioralProfile {
  userId: string;
  requestPattern: {
    avgInterval: number; // Average time between requests
    intervalStdDev: number;
    preferredUserAgents: string[];
    commonIps: string[];
    typicalNavigation: string[]; // Common request sequences
    peakActivityHours: number[]; // Hours of day with most activity
  };
  lastUpdated: Date;
}

export interface AnomalyDetectionResult {
  isAnomalous: boolean;
  confidence: number; // 0-1
  anomalyType: 'RATE' | 'NAVIGATION' | 'TIMING' | 'BEHAVIORAL';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  indicators: string[];
  riskScore: number;
  recommendation: 'ALLOW' | 'CHALLENGE' | 'BLOCK';
}

export interface TimingAnalysis {
  intervals: number[]; // Time between consecutive requests
  isHumanLike: boolean;
  entropy: number; // Randomness in timing (humans have more random timing)
  patterns: {
    regular: boolean; // Too regular (bot-like)
    tooFast: boolean; // Too fast for human
    tooConsistent: boolean; // Too consistent intervals
  };
}

export interface NavigationAnalysis {
  sequence: string[];
  isExpected: boolean;
  deviationScore: number;
  commonPaths: string[][];
  anomalyDetected: boolean;
  expectedTransitions: number;
  unexpectedTransitions: number;
}

export interface BehavioralThreat {
  id: string;
  userId: string | null;
  sessionId: string | null;
  threatType: 'AUTOMATED_ATTACK' | 'BOT_ACTIVITY' | 'SUSPICIOUS_BEHAVIOR' | 'RISKY_PATTERN';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  indicators: SuspiciousIndicator[];
  totalRiskScore: number;
  detectionTimestamp: Date;
  resolved: boolean;
  resolutionReason?: string;
  resolutionTimestamp?: Date;
}