// bot-detection.timing.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { BotDetectionService } from '../bot-detection.service';
import { RequestPattern } from '@/behavioral-analysis/types/behavior.types';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { BehavioralAnalysisService } from '@/behavioral-analysis/behavioral-analysis.service';
import { RedisService } from '@/redis/redis.service';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';
import { DeviceFingerprintingService } from '@/device-fingerprinting/device-fingerprinting.service';
import { ConfigService } from '@nestjs/config';

describe('BotDetectionService - Timing Analysis', () => {
  let service: BotDetectionService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        BotDetectionService,
        { provide: PrismaService, useValue: {} },
        { provide: EventLogService, useValue: {} },
        { provide: BehavioralAnalysisService, useValue: {} },
        { provide: RedisService, useValue: {} },
        { provide: IPReputationService, useValue: {} },
        { provide: DeviceFingerprintingService, useValue: {} },
        { provide: ConfigService, useValue: {} },
      ],
    }).compile();

    service = module.get<BotDetectionService>(BotDetectionService);
  });

  describe('Timing Pattern Analysis', () => {
    it('should detect unusually fast response times', () => {
      const request: RequestPattern = {
        timestamp: new Date(),
        method: 'GET',
        url: '/api/test',
        userAgent: 'test-agent',
        ipAddress: '192.168.1.1',
        sessionId: 'session-123',
        userId: 'user-123',
        responseTime: 5, // Very fast response time
        userAgentChange: false,
        ipChange: false,
      };

      const analysis = service['analyzeTimingPattern'](request);

      expect(analysis.isBot).toBe(true);
      expect(analysis.confidence).toBe(0.6);
      expect(analysis.indicator).toContain('Unusually fast response time: 5ms');
    });

    it('should return normal for reasonable response times', () => {
      const request: RequestPattern = {
        timestamp: new Date(),
        method: 'GET',
        url: '/api/test',
        userAgent: 'test-agent',
        ipAddress: '192.168.1.1',
        sessionId: 'session-123',
        userId: 'user-123',
        responseTime: 150, // Normal response time
        userAgentChange: false,
        ipChange: false,
      };

      const analysis = service['analyzeTimingPattern'](request);

      expect(analysis.isBot).toBe(false);
      expect(analysis.confidence).toBe(0);
      expect(analysis.indicator).toBe('Normal timing pattern');
    });

    it('should handle requests without session ID', () => {
      const request: RequestPattern = {
        timestamp: new Date(),
        method: 'GET',
        url: '/api/test',
        userAgent: 'test-agent',
        ipAddress: '192.168.1.1',
        sessionId: null, // No session ID
        userId: 'user-123',
        responseTime: 10,
        userAgentChange: false,
        ipChange: false,
      };

      const analysis = service['analyzeTimingPattern'](request);

      expect(analysis.isBot).toBe(false);
      expect(analysis.confidence).toBe(0);
      expect(analysis.indicator).toBe('First request - no timing data');
    });

    it('should handle edge case response times', () => {
      const zeroResponseTime: RequestPattern = {
        timestamp: new Date(),
        method: 'GET',
        url: '/api/test',
        userAgent: 'test-agent',
        ipAddress: '192.168.1.1',
        sessionId: 'session-123',
        userId: 'user-123',
        responseTime: 0, // Zero response time
        userAgentChange: false,
        ipChange: false,
      };

      const analysis = service['analyzeTimingPattern'](zeroResponseTime);
      expect(analysis.isBot).toBe(true); // 0ms is very fast

      const negativeResponseTime: RequestPattern = {
        timestamp: new Date(),
        method: 'GET',
        url: '/api/test',
        userAgent: 'test-agent',
        ipAddress: '192.168.1.1',
        sessionId: 'session-123',
        userId: 'user-123',
        responseTime: -100, // Negative response time
        userAgentChange: false,
        ipChange: false,
      };

      const negativeAnalysis = service['analyzeTimingPattern'](negativeResponseTime);
      expect(negativeAnalysis.isBot).toBe(true); // Negative is invalid and suspicious
    });
  });
});