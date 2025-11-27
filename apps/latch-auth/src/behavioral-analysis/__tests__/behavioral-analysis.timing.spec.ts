// behavioral-analysis.timing.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { BehavioralAnalysisService } from '../behavioral-analysis.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { SecurityMonitoringService } from '@/security/security-monitor.service';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';
import { DeviceFingerprintingService } from '@/device-fingerprinting/device-fingerprinting.service';
import { ConfigService } from '@nestjs/config';
import { JestMockExtended } from 'jest-mock-extended';

describe('BehavioralAnalysisService - Timing Analysis', () => {
  let service: BehavioralAnalysisService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        BehavioralAnalysisService,
        // Provide minimal mocks
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

  describe('Timing analysis', () => {
    it('should detect human-like timing patterns', () => {
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

      // Set up request history with human-like intervals (varied, >200ms)
      service['requestHistory'].set('test-session', [
        { timestamp: new Date(Date.now() - 4000), method: 'GET', url: '/a', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test-session', userId: 'user-123', responseTime: 150, userAgentChange: false, ipChange: false },
        { timestamp: new Date(Date.now() - 3500), method: 'GET', url: '/b', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test-session', userId: 'user-123', responseTime: 150, userAgentChange: false, ipChange: false },
        { timestamp: new Date(Date.now() - 2900), method: 'GET', url: '/c', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test-session', userId: 'user-123', responseTime: 150, userAgentChange: false, ipChange: false },
        { timestamp: new Date(Date.now() - 2200), method: 'GET', url: '/d', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test-session', userId: 'user-123', responseTime: 150, userAgentChange: false, ipChange: false },
        { timestamp: new Date(Date.now() - 1500), method: 'GET', url: '/e', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test-session', userId: 'user-123', responseTime: 150, userAgentChange: false, ipChange: false },
      ]);

      const analysis = service['analyzeTiming'](session as any, 'test-session');

      expect(analysis.isHumanLike).toBe(true);
      expect(analysis.entropy).toBeGreaterThan(0.3);
      expect(analysis.patterns.tooFast).toBe(false);
    });

    it('should detect bot-like timing patterns (too fast)', () => {
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

      // Set up request history with bot-like intervals (very fast, <50ms)
      const now = Date.now();
      service['requestHistory'].set('test-session', [
        { timestamp: new Date(now - 400), method: 'GET', url: '/a', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test-session', userId: 'user-123', responseTime: 10, userAgentChange: false, ipChange: false },
        { timestamp: new Date(now - 350), method: 'GET', url: '/b', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test-session', userId: 'user-123', responseTime: 10, userAgentChange: false, ipChange: false },
        { timestamp: new Date(now - 300), method: 'GET', url: '/c', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test-session', userId: 'user-123', responseTime: 10, userAgentChange: false, ipChange: false },
        { timestamp: new Date(now - 250), method: 'GET', url: '/d', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test-session', userId: 'user-123', responseTime: 10, userAgentChange: false, ipChange: false },
        { timestamp: new Date(now - 200), method: 'GET', url: '/e', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test-session', userId: 'user-123', responseTime: 10, userAgentChange: false, ipChange: false },
      ]);

      const analysis = service['analyzeTiming'](session as any, 'test-session');

      expect(analysis.isHumanLike).toBe(false);
      expect(analysis.patterns.tooFast).toBe(true);
    });

    it('should detect bot-like timing patterns (too consistent)', () => {
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

      // Set up request history with very consistent intervals (low entropy)
      const now = Date.now();
      service['requestHistory'].set('test-session', [
        { timestamp: new Date(now - 5000), method: 'GET', url: '/a', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test-session', userId: 'user-123', responseTime: 150, userAgentChange: false, ipChange: false },
        { timestamp: new Date(now - 4500), method: 'GET', url: '/b', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test-session', userId: 'user-123', responseTime: 150, userAgentChange: false, ipChange: false },
        { timestamp: new Date(now - 4000), method: 'GET', url: '/c', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test-session', userId: 'user-123', responseTime: 150, userAgentChange: false, ipChange: false },
        { timestamp: new Date(now - 3500), method: 'GET', url: '/d', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test-session', userId: 'user-123', responseTime: 150, userAgentChange: false, ipChange: false },
        { timestamp: new Date(now - 3000), method: 'GET', url: '/e', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test-session', userId: 'user-123', responseTime: 150, userAgentChange: false, ipChange: false },
      ]);

      const analysis = service['analyzeTiming'](session as any, 'test-session');

      expect(analysis.isHumanLike).toBe(false);
      expect(analysis.patterns.tooConsistent).toBe(true);
      expect(analysis.patterns.regular).toBe(true);
    });
  });

  describe('Entropy calculation', () => {
    it('should calculate high entropy for varied intervals', () => {
      const intervals = [100, 500, 200, 800, 300, 600];
      const entropy = service['calculateEntropy'](intervals);
      
      expect(entropy).toBeGreaterThan(0.5);
    });

    it('should calculate low entropy for identical intervals', () => {
      const intervals = [100, 100, 100, 100, 100];
      const entropy = service['calculateEntropy'](intervals);
      
      expect(entropy).toBe(0);
    });

    it('should handle empty intervals', () => {
      const entropy = service['calculateEntropy']([]);
      expect(entropy).toBe(0);
    });
  });

  describe('Regular pattern detection', () => {
    it('should detect regular patterns in intervals', () => {
      const intervals = [100, 100, 100, 100, 100];
      const hasRegularPattern = service['detectRegularPatterns'](intervals);
      
      expect(hasRegularPattern).toBe(true);
    });

    it('should not detect regular patterns in varied intervals', () => {
      const intervals = [100, 250, 80, 500, 150];
      const hasRegularPattern = service['detectRegularPatterns'](intervals);
      
      expect(hasRegularPattern).toBe(false);
    });

    it('should return false for insufficient data', () => {
      expect(service['detectRegularPatterns']([100, 150])).toBe(false);
      expect(service['detectRegularPatterns']([])).toBe(false);
    });
  });
});