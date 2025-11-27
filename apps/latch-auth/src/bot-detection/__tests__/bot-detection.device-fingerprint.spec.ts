// bot-detection.device-fingerprint.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { BotDetectionService } from '../bot-detection.service';
import { DeviceFingerprintingService } from '@/device-fingerprinting/device-fingerprinting.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { BehavioralAnalysisService } from '@/behavioral-analysis/behavioral-analysis.service';
import { RedisService } from '@/redis/redis.service';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';
import { ConfigService } from '@nestjs/config';


describe('BotDetectionService - Device Fingerprint', () => {
  let service: BotDetectionService;
  let deviceFingerprintingService: jest.Mocked<DeviceFingerprintingService>;

  const mockUserId = 'user-123';
  const mockSessionId = 'session-456';
  const mockIP = '192.168.1.1';
  const mockUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        BotDetectionService,
        {
          provide: DeviceFingerprintingService,
          useValue: {
            analyzeDeviceForBot: jest.fn(),
          },
        },
        { provide: PrismaService, useValue: {} },
        { provide: EventLogService, useValue: {} },
        { provide: BehavioralAnalysisService, useValue: {} },
        { provide: RedisService, useValue: {} },
        { provide: IPReputationService, useValue: {} },
        { provide: ConfigService, useValue: {} },
      ],
    }).compile();

    service = module.get<BotDetectionService>(BotDetectionService);
    deviceFingerprintingService = module.get(DeviceFingerprintingService);
  });

  describe('Device Fingerprint Analysis', () => {
    it('should analyze device fingerprint and return result', async () => {
      deviceFingerprintingService.analyzeDeviceForBot.mockResolvedValue({
        deviceId: 'device-123',
        isBot: false,
        confidence: 0.2,
        riskScore: 0.2,
        isSuspicious: false,
        indicators: [],
        recommendation: 'ALLOW',
        similarityScore: 0.8,
        matchedDevices: ['device-456'],
        isNewDevice: false,
        analysis: {
          userAgent: false,
          deviceType: false,
          browser: false,
          os: false,
          timing: false,
          pattern: false,
        },
        firstSeen: new Date('2023-01-01'),
        lastSeen: new Date(),
      });

      const analysis = await service['analyzeDeviceFingerprint'](
        mockUserId,
        mockSessionId,
        mockUserAgent,
        mockIP,
        'GET',
        '/api/test',
        150
      );

      expect(analysis.isBot).toBe(false);
      expect(analysis.confidence).toBe(0.2);
      expect(analysis.indicator).toContain('Device fingerprint analysis');
    });

    it('should detect bot from device analysis', async () => {
      deviceFingerprintingService.analyzeDeviceForBot.mockResolvedValue({
        deviceId: 'device-bot-123',
        isBot: true,
        confidence: 0.9,
        riskScore: 0.9,
        isSuspicious: true,
        indicators: ['Known bot signature: HeadlessChrome'],
        recommendation: 'BLOCK',
        similarityScore: 0.1,
        matchedDevices: [],
        isNewDevice: true,
        analysis: {
          userAgent: true,
          deviceType: true,
          browser: true,
          os: true,
          timing: true,
          pattern: true,
        },
        firstSeen: new Date(),
        lastSeen: new Date(),
      });

      const analysis = await service['analyzeDeviceFingerprint'](
        mockUserId,
        mockSessionId,
        'HeadlessChrome',
        mockIP,
        'GET',
        '/api/test',
        10
      );

      expect(analysis.isBot).toBe(true);
      expect(analysis.confidence).toBe(0.9);
      expect(analysis.indicator).toContain('Device fingerprint analysis');
    });

    it('should handle missing user agent and IP', async () => {
      const analysis = await service['analyzeDeviceFingerprint'](
        mockUserId,
        mockSessionId,
        null, // No user agent
        null, // No IP
        'GET',
        '/api/test',
        150
      );

      expect(analysis.isBot).toBe(false);
      expect(analysis.confidence).toBe(0);
      expect(analysis.indicator).toBe('Missing device data');
    });

    it('should handle device analysis errors gracefully', async () => {
      deviceFingerprintingService.analyzeDeviceForBot.mockRejectedValue(
        new Error('Device analysis service unavailable')
      );

      const analysis = await service['analyzeDeviceFingerprint'](
        mockUserId,
        mockSessionId,
        mockUserAgent,
        mockIP,
        'GET',
        '/api/test',
        150
      );

      expect(analysis.isBot).toBe(false);
      expect(analysis.confidence).toBe(0);
      expect(analysis.indicator).toBe('Device analysis error');
    });
  });
});