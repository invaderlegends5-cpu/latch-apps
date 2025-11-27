import { EventType } from '../../events/event.types';

export const IP_REPUTATION_CONFIG = {
  scoring: {
    weights: {
      // High severity - immediate blocking potential
      TOKEN_REUSE: 100,
      SECURITY_CSRF_MISMATCH: 80,
      AUTH_JWT_FAILURE: 70,
      REFRESH_FAILED: 60,
      
      // Medium severity - accumulating risk
      OTP_FAILED: 15,
      USER_DATA_ACCESS_ATTEMPT: 10,
      ROLE_ACCESS_DENIED: 10,
      PRIVILEGE_ACCESS_DENIED: 10,
      
      // Low severity - monitoring
      LOGIN: 1,
      LOGOUT: 0,
      OTP_REQUEST: 2,
      SESSION_EXPIRED: 0,
      USER_PROFILE_UPDATE: 0,
      
      // All other events default to 0
    } as Record<EventType, number>,
    
    decayRate: 0.95, // Daily decay rate (5% per day)
    maxScore: 1000,
    minScore: -100,
  },
  
  blocking: {
    thresholds: {
      medium: 50,
      high: 150,
      critical: 300,
    },
    autoBlock: true,
    blockDuration: 60 * 60 * 1000, // 1 hour in milliseconds
    maxBlockDuration: 7 * 24 * 60 * 60 * 1000, // 7 days
  },
  
  monitoring: {
    anomalyDetection: true,
    geoRiskAnalysis: true,
    behavioralAnalysis: true,
  },
  
  retention: {
    historyDays: 90,
    threatIndicatorsDays: 30,
  },
} as const;

export const THREAT_INDICATORS = {
  BRUTE_FORCE: {
    threshold: 10, // failed attempts within 5 minutes
    window: 5 * 60 * 1000, // 5 minutes in ms
    severity: 'HIGH' as const,
    scoreImpact: 100,
  },
  DDOS: {
    threshold: 100, // requests within 1 minute
    window: 60 * 1000, // 1 minute in ms
    severity: 'CRITICAL' as const,
    scoreImpact: 200,
  },
  GEO_RISK: {
    severity: 'MEDIUM' as const,
    scoreImpact: 50,
  },
} as const;

export const RISK_LEVEL_THRESHOLDS = {
  LOW: { min: -100, max: 49 },
  MEDIUM: { min: 50, max: 149 },
  HIGH: { min: 150, max: 299 },
  CRITICAL: { min: 300, max: 1000 },
} as const;