// src/bot-detection/__tests__/bot-detection.service.unit.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { BotDetectionService } from '../bot-detection.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { BehavioralAnalysisService } from '@/behavioral-analysis/behavioral-analysis.service';
import { RedisService } from '@/redis/redis.service';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';
import { DeviceFingerprintingService } from '@/device-fingerprinting/device-fingerprinting.service';
import { ConfigService } from '@nestjs/config';
import { SecurityMonitoringService } from '@/security/security-monitor.service';

describe('BotDetectionService', () => {
  let service: BotDetectionService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        BotDetectionService,
        PrismaService,
        EventLogService,
        {
          provide: SecurityMonitoringService, // ADD THIS - needed by BehavioralAnalysisService
          useValue: {
            handleEvent: jest.fn(),
            // Add other methods that BehavioralAnalysisService might call
          },
        },
        BehavioralAnalysisService,
        { provide: RedisService, useValue: {} },
        IPReputationService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn().mockImplementation((key: string) => {
              // You can implement specific returns for specific keys if needed
              // or just return a default value for all keys during testing
              if (key === 'EVENT_SIGNING_SECRET') {
                return 'test-signing-secret';
              }
              return null; // Default return for other keys
            }),
          },
        },

        DeviceFingerprintingService,
      ],
    }).compile();

    service = module.get<BotDetectionService>(BotDetectionService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('analyzeRequest', () => {
    it('should detect bot behavior', async () => {
      const result = await service.analyzeRequest(
        'user-123',
        'session-123',
        '192.168.1.1',
        'Googlebot/2.1',
        'GET',
        '/api/users',
      );

      expect(result).toBeDefined();
      expect(typeof result.isBot).toBe('boolean');
      expect(result.indicators).toBeInstanceOf(Array);
    });

    it('should allow human-like requests', async () => {
      const result = await service.analyzeRequest(
        'user-123',
        'session-123',
        '192.168.1.100',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'GET',
        '/api/profile',
      );

      expect(result.isBot).toBe(false);
      expect(result.recommendation).toBe('ALLOW');
    });
  });
});