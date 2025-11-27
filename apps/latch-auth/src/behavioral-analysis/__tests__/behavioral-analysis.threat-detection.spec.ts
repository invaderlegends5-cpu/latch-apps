// behavioral-analysis.threat-detection.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { BehavioralAnalysisService } from '../behavioral-analysis.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { SecurityMonitoringService } from '@/security/security-monitor.service';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';
import { DeviceFingerprintingService } from '@/device-fingerprinting/device-fingerprinting.service';
import { ConfigService } from '@nestjs/config';
import { BehavioralSession, BehavioralThreat, SuspiciousIndicator } from '../types/behavior.types';

describe('BehavioralAnalysisService - Threat Detection', () => {
  let service: BehavioralAnalysisService;
  let eventLogService: jest.Mocked<EventLogService>;

  const mockUserId = 'user-123';
  const mockSessionId = 'session-456';
  const mockIP = '192.168.1.1';

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        BehavioralAnalysisService,
        {
          provide: PrismaService,
          useValue: {},
        },
        {
          provide: EventLogService,
          useValue: {
            logEvent: jest.fn(),
          },
        },
        {
          provide: SecurityMonitoringService,
          useValue: {},
        },
        {
          provide: IPReputationService,
          useValue: {},
        },
        {
          provide: DeviceFingerprintingService,
          useValue: {},
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<BehavioralAnalysisService>(BehavioralAnalysisService);
    eventLogService = module.get(EventLogService);
  });

  describe('Threat Creation', () => {
    it('should create threat alert for high-risk behavior', async () => {
      const session: BehavioralSession = {
        sessionId: mockSessionId,
        userId: mockUserId,
        ipAddress: mockIP,
        userAgent: 'test-agent',
        firstRequest: new Date(),
        lastRequest: new Date(),
        totalRequests: 25,
        requestIntervalStats: { mean: 50, stdDev: 5, min: 45, max: 55 }, // Very consistent
        navigationSequence: ['/api/a', '/api/b', '/api/c'],
        suspiciousIndicators: [],
        riskScore: 0.85,
        riskLevel: 'HIGH',
      };

      const additionalIndicators: SuspiciousIndicator[] = [{
        type: 'RATE_ANOMALY',
        severity: 'HIGH',
        evidence: 'High request rate detected',
        timestamp: new Date(),
        scoreImpact: 0.3,
      }];

      await service['createThreatAlert'](session, 0.85, 'HIGH', additionalIndicators);

      // Check that threat was created in cache
      const threats = Array.from(service['threatCache'].values());
      expect(threats).toHaveLength(1);

      const threat = threats[0];
      expect(threat.userId).toBe(mockUserId);
      expect(threat.sessionId).toBe(mockSessionId);
      expect(threat.threatType).toBe('SUSPICIOUS_BEHAVIOR');
      expect(threat.severity).toBe('HIGH');
      expect(threat.totalRiskScore).toBe(0.85);
      expect(threat.resolved).toBe(false);
      expect(threat.indicators).toHaveLength(2); // One from getThreatIndicators + additional

      // Check that event was logged
      expect(eventLogService.logEvent).toHaveBeenCalledWith(
        'SECURITY_CSRF_ERROR',
        expect.objectContaining({
          userId: mockUserId,
          ipAddress: mockIP,
          metadata: expect.objectContaining({
            reason: 'behavioral_threat_detected',
            threatId: threat.id,
            riskScore: 0.85,
            severity: 'HIGH',
          }),
        })
      );
    });

    it('should generate unique threat IDs', async () => {
      const session: BehavioralSession = {
        sessionId: mockSessionId,
        userId: mockUserId,
        ipAddress: mockIP,
        userAgent: 'test-agent',
        firstRequest: new Date(),
        lastRequest: new Date(),
        totalRequests: 10,
        requestIntervalStats: { mean: 0, stdDev: 0, min: 0, max: 0 },
        navigationSequence: [],
        suspiciousIndicators: [],
        riskScore: 0.9,
        riskLevel: 'HIGH',
      };

      await service['createThreatAlert'](session, 0.9, 'HIGH');
      await service['createThreatAlert'](session, 0.9, 'HIGH');

      const threats = Array.from(service['threatCache'].values());
      expect(threats).toHaveLength(2);
      
      const threatIds = threats.map(t => t.id);
      const uniqueIds = new Set(threatIds);
      expect(uniqueIds.size).toBe(2); // All IDs should be unique
    });
  });

  describe('Threat Indicators', () => {
    it('should generate threat indicators for suspicious session', () => {
      const session: BehavioralSession = {
        sessionId: mockSessionId,
        userId: mockUserId,
        ipAddress: mockIP,
        userAgent: 'test-agent',
        firstRequest: new Date(),
        lastRequest: new Date(),
        totalRequests: 15,
        requestIntervalStats: { mean: 100, stdDev: 2, min: 98, max: 102 }, // Very consistent
        navigationSequence: [],
        suspiciousIndicators: [],
        riskScore: 0.7,
        riskLevel: 'HIGH',
      };

      const indicators = service['getThreatIndicators'](session);

      expect(indicators).toHaveLength(1);
      expect(indicators[0].type).toBe('TIMING_ANOMALY');
      expect(indicators[0].severity).toBe('HIGH');
      expect(indicators[0].evidence).toBe('Very consistent request intervals');
      expect(indicators[0].scoreImpact).toBe(0.3);
    });

    it('should not generate indicators for normal session', () => {
      const session: BehavioralSession = {
        sessionId: mockSessionId,
        userId: mockUserId,
        ipAddress: mockIP,
        userAgent: 'test-agent',
        firstRequest: new Date(),
        lastRequest: new Date(),
        totalRequests: 15,
        requestIntervalStats: { mean: 1000, stdDev: 500, min: 500, max: 1500 }, // Normal variation
        navigationSequence: [],
        suspiciousIndicators: [],
        riskScore: 0.2,
        riskLevel: 'LOW',
      };

      const indicators = service['getThreatIndicators'](session);

      expect(indicators).toHaveLength(0);
    });
  });

  describe('Anomaly Type Determination', () => {
    it('should prioritize rate anomalies', () => {
      const timingAnalysis = { isHumanLike: false } as any;
      const navigationAnalysis = { anomalyDetected: true } as any;
      const rateAnalysis = { isAnomalous: true } as any;

      const anomalyType = service['determineAnomalyType'](timingAnalysis, navigationAnalysis, rateAnalysis);

      expect(anomalyType).toBe('RATE');
    });

    it('should prioritize navigation anomalies over timing', () => {
      const timingAnalysis = { isHumanLike: false } as any;
      const navigationAnalysis = { anomalyDetected: true } as any;
      const rateAnalysis = { isAnomalous: false } as any;

      const anomalyType = service['determineAnomalyType'](timingAnalysis, navigationAnalysis, rateAnalysis);

      expect(anomalyType).toBe('NAVIGATION');
    });

    it('should detect timing anomalies', () => {
      const timingAnalysis = { isHumanLike: false } as any;
      const navigationAnalysis = { anomalyDetected: false } as any;
      const rateAnalysis = { isAnomalous: false } as any;

      const anomalyType = service['determineAnomalyType'](timingAnalysis, navigationAnalysis, rateAnalysis);

      expect(anomalyType).toBe('TIMING');
    });

    it('should default to behavioral for no specific anomalies', () => {
      const timingAnalysis = { isHumanLike: true } as any;
      const navigationAnalysis = { anomalyDetected: false } as any;
      const rateAnalysis = { isAnomalous: false } as any;

      const anomalyType = service['determineAnomalyType'](timingAnalysis, navigationAnalysis, rateAnalysis);

      expect(anomalyType).toBe('BEHAVIORAL');
    });
  });
});