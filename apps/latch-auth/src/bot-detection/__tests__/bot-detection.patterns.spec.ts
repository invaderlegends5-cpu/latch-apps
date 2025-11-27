// bot-detection.patterns.spec.ts
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

describe('BotDetectionService - Request Pattern Analysis', () => {
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

  describe('Request Pattern Analysis', () => {
    it('should detect suspicious URL patterns', () => {
      const suspiciousUrls = [
        '/admin',
        '/wp-admin',
        '/phpmyadmin',
        '/backup',
        '/config',
        '/private',
        '/api/graphql',
        '/graphql',
        '/api/v1/users',
        '/api/v2/admin',
      ];

      suspiciousUrls.forEach(url => {
        const request: RequestPattern = {
          timestamp: new Date(),
          method: 'GET',
          url,
          userAgent: 'test-agent',
          ipAddress: '192.168.1.1',
          sessionId: 'session-123',
          userId: 'user-123',
          responseTime: 150,
          userAgentChange: false,
          ipChange: false,
        };

        const analysis = service['analyzeRequestPattern'](request);

        expect(analysis.isBot).toBe(true);
        expect(analysis.confidence).toBe(0.4);
        expect(analysis.indicator).toContain('Suspicious URL pattern accessed');
      });
    });

    it('should detect suspicious HTTP methods', () => {
      const suspiciousMethods = ['TRACE', 'CONNECT', 'OPTIONS'];

      suspiciousMethods.forEach(method => {
        const request: RequestPattern = {
          timestamp: new Date(),
          method,
          url: '/api/test',
          userAgent: 'test-agent',
          ipAddress: '192.168.1.1',
          sessionId: 'session-123',
          userId: 'user-123',
          responseTime: 150,
          userAgentChange: false,
          ipChange: false,
        };

        const analysis = service['analyzeRequestPattern'](request);

        expect(analysis.isBot).toBe(true);
        expect(analysis.confidence).toBe(0.5);
        expect(analysis.indicator).toContain(`Suspicious HTTP method: ${method}`);
      });
    });

    it('should return normal for safe URLs and methods', () => {
      const safeRequests = [
        {
          method: 'GET',
          url: '/api/users/me/profile',
        },
        {
          method: 'POST',
          url: '/api/auth/login',
        },
        {
          method: 'PUT',
          url: '/api/users/123',
        },
        {
          method: 'DELETE',
          url: '/api/sessions/456',
        },
      ];

      safeRequests.forEach(({ method, url }) => {
        const request: RequestPattern = {
          timestamp: new Date(),
          method,
          url,
          userAgent: 'test-agent',
          ipAddress: '192.168.1.1',
          sessionId: 'session-123',
          userId: 'user-123',
          responseTime: 150,
          userAgentChange: false,
          ipChange: false,
        };

        const analysis = service['analyzeRequestPattern'](request);

        expect(analysis.isBot).toBe(false);
        expect(analysis.confidence).toBe(0);
        expect(analysis.indicator).toBe('Normal request pattern');
      });
    });

    it('should handle case-insensitive URL matching', () => {
      const mixedCaseUrls = [
        '/ADMIN',
        '/Wp-Admin',
        '/PHPMyAdmin',
        '/BACKUP',
      ];

      mixedCaseUrls.forEach(url => {
        const request: RequestPattern = {
          timestamp: new Date(),
          method: 'GET',
          url,
          userAgent: 'test-agent',
          ipAddress: '192.168.1.1',
          sessionId: 'session-123',
          userId: 'user-123',
          responseTime: 150,
          userAgentChange: false,
          ipChange: false,
        };

        const analysis = service['analyzeRequestPattern'](request);

        expect(analysis.isBot).toBe(true);
        expect(analysis.indicator).toContain('Suspicious URL pattern accessed');
      });
    });
  });
});