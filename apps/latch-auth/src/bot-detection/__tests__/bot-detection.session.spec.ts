// bot-detection.session.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { BotDetectionService } from '../bot-detection.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { BehavioralAnalysisService } from '@/behavioral-analysis/behavioral-analysis.service';
import { RedisService } from '@/redis/redis.service';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';
import { DeviceFingerprintingService } from '@/device-fingerprinting/device-fingerprinting.service';
import { ConfigService } from '@nestjs/config';

describe('BotDetectionService - Session Behavior Analysis', () => {
  let service: BotDetectionService;
  let prismaService: jest.Mocked<PrismaService>;

  const mockSessionId = 'session-456';
  const mockUserId = 'user-123';

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        BotDetectionService,
        {
          provide: PrismaService,
          useValue: {
            session: {
              findUnique: jest.fn(),
            },
          },
        },
        { provide: EventLogService, useValue: {} },
        { provide: BehavioralAnalysisService, useValue: {} },
        { provide: RedisService, useValue: {} },
        { provide: IPReputationService, useValue: {} },
        { provide: DeviceFingerprintingService, useValue: {} },
        { provide: ConfigService, useValue: {} },
      ],
    }).compile();

    service = module.get<BotDetectionService>(BotDetectionService);
    prismaService = module.get(PrismaService);
  });

  describe('Session Behavior Analysis', () => {
    it('should analyze session and return normal behavior for valid session', async () => {
      prismaService.session.findUnique.mockResolvedValue({
        id: mockSessionId,
        userId: mockUserId,
        tenantId: 'tenant-123',
        refreshHash: 'hash',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ipAddress: '192.168.1.1',
        createdAt: new Date(),
        lastActiveAt: new Date(),
        expiresAt: new Date(Date.now() + 3600000),
        revoked: false,
        csrfToken: 'csrf-token',
      });

      const analysis = await service['analyzeSessionBehavior'](mockSessionId);

      expect(analysis.isBot).toBe(false);
      expect(analysis.confidence).toBe(0);
      expect(analysis.indicator).toBe('Normal session behavior');
    });

    it('should handle session not found', async () => {
      prismaService.session.findUnique.mockResolvedValue(null);

      const analysis = await service['analyzeSessionBehavior'](mockSessionId);

      expect(analysis.isBot).toBe(false);
      expect(analysis.confidence).toBe(0);
      expect(analysis.indicator).toBe('Session not found');
    });

    it('should handle null session ID', async () => {
      const analysis = await service['analyzeSessionBehavior'](null);

      expect(analysis.isBot).toBe(false);
      expect(analysis.confidence).toBe(0);
      expect(analysis.indicator).toBe('No session context');
    });

    it('should handle database errors gracefully', async () => {
      prismaService.session.findUnique.mockRejectedValue(new Error('Database connection failed'));

      const analysis = await service['analyzeSessionBehavior'](mockSessionId);

      expect(analysis.isBot).toBe(false);
      expect(analysis.confidence).toBe(0);
      expect(analysis.indicator).toBe('Session analysis error');
    });

    it('should analyze session with minimal data', async () => {
      prismaService.session.findUnique.mockResolvedValue({
        id: mockSessionId,
        userId: mockUserId,
        tenantId: null,
        refreshHash: 'hash',
        userAgent: null,
        ipAddress: null,
        createdAt: new Date(),
        lastActiveAt: new Date(),
        expiresAt: new Date(Date.now() + 3600000),
        revoked: false,
        csrfToken: null,
      });

      const analysis = await service['analyzeSessionBehavior'](mockSessionId);

      expect(analysis.isBot).toBe(false);
      expect(analysis.confidence).toBe(0);
      expect(analysis.indicator).toBe('Normal session behavior');
    });
  });
});