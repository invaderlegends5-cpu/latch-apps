// behavioral-analysis.rate.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { BehavioralAnalysisService } from '../behavioral-analysis.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { SecurityMonitoringService } from '@/security/security-monitor.service';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';
import { DeviceFingerprintingService } from '@/device-fingerprinting/device-fingerprinting.service';
import { ConfigService } from '@nestjs/config';

describe('BehavioralAnalysisService - Rate Analysis', () => {
  let service: BehavioralAnalysisService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        BehavioralAnalysisService,
        { provide: PrismaService, useValue: {} },
        { provide: EventLogService, useValue: {} },
        { provide: SecurityMonitoringService, useValue: {} },
        { provide: IPReputationService, useValue: {} },
        { provide: DeviceFingerprintingService, useValue: {} },
        { provide: ConfigService, useValue: {get: jest.fn()} },
      ],
    }).compile();

    service = module.get<BehavioralAnalysisService>(BehavioralAnalysisService);
  });

  describe('Rate analysis', () => {
    it('should detect normal request rates', () => {
      const session = {
        sessionId: 'test-session',
        userId: 'user-123',
        ipAddress: '192.168.1.1',
        userAgent: 'test-agent',
        firstRequest: new Date(),
        lastRequest: new Date(),
        totalRequests: 5,
        requestIntervalStats: { mean: 0, stdDev: 0, min: 0, max: 0 },
        navigationSequence: [],
        suspiciousIndicators: [],
        riskScore: 0,
        riskLevel: 'LOW',
      };

      // Set up moderate request history
      const now = Date.now();
      const requests = Array.from({ length: 10 }, (_, i) => ({
        timestamp: new Date(now - (i * 5000)), // 5 seconds apart
        method: 'GET',
        url: `/api/test${i}`,
        userAgent: 'test',
        ipAddress: '192.168.1.1',
        sessionId: 'test-session',
        userId: 'user-123',
        responseTime: 150,
        userAgentChange: false,
        ipChange: false,
      }));

      service['requestHistory'].set('test-session', requests);

      const analysis = service['analyzeRate'](session as any, 'test-session');

      expect(analysis.isAnomalous).toBe(false);
      expect(analysis.rate).toBe(10);
      expect(analysis.burstiness).toBeLessThan(0.5);
    });

    it('should detect high request rates as anomalous', () => {
      const session = {
        sessionId: 'test-session',
        userId: 'user-123',
        ipAddress: '192.168.1.1',
        userAgent: 'test-agent',
        firstRequest: new Date(),
        lastRequest: new Date(),
        totalRequests: 25,
        requestIntervalStats: { mean: 0, stdDev: 0, min: 0, max: 0 },
        navigationSequence: [],
        suspiciousIndicators: [],
        riskScore: 0,
        riskLevel: 'LOW',
      };

      // Set up high frequency requests
      const now = Date.now();
      const requests = Array.from({ length: 25 }, (_, i) => ({
        timestamp: new Date(now - (i * 1000)), // 1 second apart
        method: 'GET',
        url: `/api/test${i}`,
        userAgent: 'test',
        ipAddress: '192.168.1.1',
        sessionId: 'test-session',
        userId: 'user-123',
        responseTime: 50,
        userAgentChange: false,
        ipChange: false,
      }));

      service['requestHistory'].set('test-session', requests);

      const analysis = service['analyzeRate'](session as any, 'test-session');

      expect(analysis.isAnomalous).toBe(true);
      expect(analysis.rate).toBe(25);
    });

    it('should detect bursty request patterns', () => {
      const session = {
        sessionId: 'test-session',
        userId: 'user-123',
        ipAddress: '192.168.1.1',
        userAgent: 'test-agent',
        firstRequest: new Date(),
        lastRequest: new Date(),
        totalRequests: 8,
        requestIntervalStats: { mean: 0, stdDev: 0, min: 0, max: 0 },
        navigationSequence: [],
        suspiciousIndicators: [],
        riskScore: 0,
        riskLevel: 'LOW',
      };

      // Set up bursty pattern (clustered requests)
      const now = Date.now();
      const requests = [
        { timestamp: new Date(now - 60000), method: 'GET', url: '/a', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test-session', userId: 'user-123', responseTime: 150, userAgentChange: false, ipChange: false },
        { timestamp: new Date(now - 59000), method: 'GET', url: '/b', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test-session', userId: 'user-123', responseTime: 150, userAgentChange: false, ipChange: false },
        { timestamp: new Date(now - 58000), method: 'GET', url: '/c', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test-session', userId: 'user-123', responseTime: 150, userAgentChange: false, ipChange: false },
        { timestamp: new Date(now - 57000), method: 'GET', url: '/d', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test-session', userId: 'user-123', responseTime: 150, userAgentChange: false, ipChange: false },
        { timestamp: new Date(now - 10000), method: 'GET', url: '/e', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test-session', userId: 'user-123', responseTime: 150, userAgentChange: false, ipChange: false },
        { timestamp: new Date(now - 9000), method: 'GET', url: '/f', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test-session', userId: 'user-123', responseTime: 150, userAgentChange: false, ipChange: false },
        { timestamp: new Date(now - 8000), method: 'GET', url: '/g', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test-session', userId: 'user-123', responseTime: 150, userAgentChange: false, ipChange: false },
        { timestamp: new Date(now - 7000), method: 'GET', url: '/h', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test-session', userId: 'user-123', responseTime: 150, userAgentChange: false, ipChange: false },
      ];

      service['requestHistory'].set('test-session', requests);

      const analysis = service['analyzeRate'](session as any, 'test-session');

      expect(analysis.burstiness).toBeGreaterThan(0.8);
    });
  });

  describe('Burstiness calculation', () => {
    it('should calculate high burstiness for clustered requests', () => {
      const requests = [
        { timestamp: new Date(1000), method: 'GET', url: '/a', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test', userId: 'user', responseTime: 150, userAgentChange: false, ipChange: false },
        { timestamp: new Date(1100), method: 'GET', url: '/b', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test', userId: 'user', responseTime: 150, userAgentChange: false, ipChange: false },
        { timestamp: new Date(1200), method: 'GET', url: '/c', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test', userId: 'user', responseTime: 150, userAgentChange: false, ipChange: false },
        { timestamp: new Date(5000), method: 'GET', url: '/d', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test', userId: 'user', responseTime: 150, userAgentChange: false, ipChange: false },
      ];

      const burstiness = service['calculateRateBurstiness'](requests);
      
      expect(burstiness).toBeGreaterThan(1); // High burstiness
    });

    it('should calculate low burstiness for evenly spaced requests', () => {
      const requests = [
        { timestamp: new Date(1000), method: 'GET', url: '/a', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test', userId: 'user', responseTime: 150, userAgentChange: false, ipChange: false },
        { timestamp: new Date(2000), method: 'GET', url: '/b', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test', userId: 'user', responseTime: 150, userAgentChange: false, ipChange: false },
        { timestamp: new Date(3000), method: 'GET', url: '/c', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test', userId: 'user', responseTime: 150, userAgentChange: false, ipChange: false },
        { timestamp: new Date(4000), method: 'GET', url: '/d', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test', userId: 'user', responseTime: 150, userAgentChange: false, ipChange: false },
      ];

      const burstiness = service['calculateRateBurstiness'](requests);
      
      expect(burstiness).toBeLessThan(0.5); // Low burstiness
    });

    it('should return 0 for insufficient data', () => {
      const burstiness1 = service['calculateRateBurstiness']([]);
      const burstiness2 = service['calculateRateBurstiness']([{ timestamp: new Date(), method: 'GET', url: '/a', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test', userId: 'user', responseTime: 150, userAgentChange: false, ipChange: false }]);
      
      expect(burstiness1).toBe(0);
      expect(burstiness2).toBe(0);
    });
  });
});