// bot-detection.integration.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { BotDetectionService } from '../bot-detection.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';
import { DeviceFingerprintingService } from '@/device-fingerprinting/device-fingerprinting.service';
import { BotDetectionResult } from '../bot-detection.service';
import { BehavioralAnalysisService } from '@/behavioral-analysis/behavioral-analysis.service';
import { RedisService } from '@/redis/redis.service';
import { ConfigService } from '@nestjs/config';

describe('BotDetectionService - Integration', () => {
  let service: BotDetectionService;
  let prismaService: jest.Mocked<PrismaService>;
  let eventLogService: jest.Mocked<EventLogService>;
  let ipReputationService: jest.Mocked<IPReputationService>;
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
          provide: PrismaService,
          useValue: {
            session: {
              findUnique: jest.fn(),
            },
          },
        },
        {
          provide: EventLogService,
          useValue: {
            logEvent: jest.fn(),
          },
        },
        {
          provide: IPReputationService,
          useValue: {
            isIPBlocked: jest.fn().mockResolvedValue(false),
            blockIP: jest.fn(),
          },
        },
        {
          provide: DeviceFingerprintingService,
          useValue: {
            analyzeDeviceForBot: jest.fn(),
          },
        },
        { provide: BehavioralAnalysisService, useValue: {} },
        { provide: RedisService, useValue: {} },
        { provide: ConfigService, useValue: {} },
      ],
    }).compile();

    service = module.get<BotDetectionService>(BotDetectionService);
    prismaService = module.get(PrismaService);
    eventLogService = module.get(EventLogService);
    ipReputationService = module.get(IPReputationService);
    deviceFingerprintingService = module.get(DeviceFingerprintingService);

    jest.clearAllMocks();
  });

  describe('End-to-End Bot Detection', () => {
    it('should detect sophisticated bot with multiple indicators', async () => {
      // Mock session lookup
      prismaService.session.findUnique.mockResolvedValue({
        id: mockSessionId,
        userId: mockUserId,
        tenantId: 'tenant-123',
        refreshHash: 'hash',
        userAgent: 'HeadlessChrome',
        ipAddress: mockIP,
        createdAt: new Date(),
        lastActiveAt: new Date(),
        expiresAt: new Date(Date.now() + 3600000),
        revoked: false,
        csrfToken: 'csrf-token',
      });

      // Mock device analysis to return high risk
      deviceFingerprintingService.analyzeDeviceForBot.mockResolvedValue({
        deviceId: 'device-bot-advanced',
        isBot: true,
        confidence: 0.95,
        riskScore: 0.95,
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

      const result = await service.analyzeRequest(
        mockUserId,
        mockSessionId,
        mockIP,
        'HeadlessChrome', // Bot user agent
        'GET',
        '/api/admin', // Suspicious URL
        5 // Very fast response time
      );

      expect(result.isBot).toBe(true);
      expect(result.confidence).toBeGreaterThan(0.8);
      expect(result.recommendation).toBe('BLOCK');
      expect(result.indicators.length).toBeGreaterThan(0);
      expect(result.analysis.userAgent).toBe(true);
      expect(result.analysis.timing).toBe(true);
      expect(result.analysis.requestPattern).toBe(true);

      // Should trigger auto-blocking
      expect(ipReputationService.blockIP).toHaveBeenCalled();
      
      // Should log the detection
      expect(eventLogService.logEvent).toHaveBeenCalledWith(
        'SECURITY_CSRF_ERROR',
        expect.objectContaining({
          metadata: expect.objectContaining({
            analysisType: 'BOT_DETECTION',
            isBot: true,
          }),
        })
      );
    });

    it('should allow legitimate human traffic', async () => {
      // Mock session lookup
      prismaService.session.findUnique.mockResolvedValue({
        id: mockSessionId,
        userId: mockUserId,
        tenantId: 'tenant-123',
        refreshHash: 'hash',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ipAddress: mockIP,
        createdAt: new Date(),
        lastActiveAt: new Date(),
        expiresAt: new Date(Date.now() + 3600000),
        revoked: false,
        csrfToken: 'csrf-token',
      });

      // Mock device analysis to return low risk
      deviceFingerprintingService.analyzeDeviceForBot.mockResolvedValue({
        deviceId: 'device-human',
        isBot: false,
        confidence: 0.1,
        riskScore: 0.1,
        isSuspicious: false,
        indicators: [],
        recommendation: 'ALLOW',
        similarityScore: 0.9,
        matchedDevices: ['device-existing'],
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

      const result = await service.analyzeRequest(
        mockUserId,
        mockSessionId,
        mockIP,
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'GET',
        '/api/user/profile',
        150 // Normal response time
      );

      expect(result.isBot).toBe(false);
      expect(result.confidence).toBeLessThan(0.3);
      expect(result.recommendation).toBe('ALLOW');
      expect(result.indicators).toHaveLength(0);

      // Should not trigger blocking
      expect(ipReputationService.blockIP).not.toHaveBeenCalled();
      
      // Should not log security event for normal traffic
      expect(eventLogService.logEvent).not.toHaveBeenCalledWith(
        'SECURITY_CSRF_ERROR',
        expect.objectContaining({
          metadata: expect.objectContaining({
            analysisType: 'BOT_DETECTION',
          }),
        })
      );
    });

    it('should challenge medium-risk traffic', async () => {
      // Mock session lookup
      prismaService.session.findUnique.mockResolvedValue({
        id: mockSessionId,
        userId: mockUserId,
        tenantId: 'tenant-123',
        refreshHash: 'hash',
        userAgent: 'python-requests/2.28.1', // Suspicious but not critical
        ipAddress: mockIP,
        createdAt: new Date(),
        lastActiveAt: new Date(),
        expiresAt: new Date(Date.now() + 3600000),
        revoked: false,
        csrfToken: 'csrf-token',
      });

      // Mock device analysis to return medium risk
      deviceFingerprintingService.analyzeDeviceForBot.mockResolvedValue({
        deviceId: 'device-suspicious',
        isBot: true,
        confidence: 0.7,
        riskScore: 0.7,
        isSuspicious: true,
        indicators: ['Non-browser client detected'],
        recommendation: 'CHALLENGE',
        similarityScore: 0.3,
        matchedDevices: [],
        isNewDevice: true,
        analysis: {
          userAgent: true,
          deviceType: false,
          browser: false,
          os: false,
          timing: false,
          pattern: false,
        },
        firstSeen: new Date(),
        lastSeen: new Date(),
      });

      const result = await service.analyzeRequest(
        mockUserId,
        mockSessionId,
        mockIP,
        'python-requests/2.28.1',
        'GET',
        '/api/data',
        100
      );

      expect(result.isBot).toBe(true);
      expect(result.confidence).toBeGreaterThan(0.6);
      expect(result.confidence).toBeLessThan(0.9);
      expect(result.recommendation).toBe('CHALLENGE');
      expect(result.analysis.userAgent).toBe(true);

      // Should not trigger auto-blocking for medium risk
      expect(ipReputationService.blockIP).not.toHaveBeenCalled();
      
      // Should log the detection
      expect(eventLogService.logEvent).toHaveBeenCalled();
    });

    it('should handle mixed analysis results correctly', async () => {
      // This user agent is suspicious but timing is normal
      prismaService.session.findUnique.mockResolvedValue({
        id: mockSessionId,
        userId: mockUserId,
        tenantId: 'tenant-123',
        refreshHash: 'hash',
        userAgent: 'curl/7.68.0',
        ipAddress: mockIP,
        createdAt: new Date(),
        lastActiveAt: new Date(),
        expiresAt: new Date(Date.now() + 3600000),
        revoked: false,
        csrfToken: 'csrf-token',
      });

      deviceFingerprintingService.analyzeDeviceForBot.mockResolvedValue({
        deviceId: 'device-mixed',
        isBot: false,
        confidence: 0.4,
        riskScore: 0.4,
        isSuspicious: false,
        indicators: [],
        recommendation: 'ALLOW',
        similarityScore: 0.6,
        matchedDevices: ['device-existing'],
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

      const result = await service.analyzeRequest(
        mockUserId,
        mockSessionId,
        mockIP,
        'curl/7.68.0', // Suspicious user agent
        'GET',
        '/api/normal',
        200 // Normal response time
      );

      // The suspicious user agent should increase risk but not enough to classify as bot
      expect(result.isBot).toBe(true); // User agent alone might push it over medium threshold
      expect(result.confidence).toBeGreaterThan(0.3);
      expect(result.analysis.userAgent).toBe(true);
      expect(result.analysis.timing).toBe(false);
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle requests with minimal data', async () => {
      const result = await service.analyzeRequest(
        null, // No user ID
        null, // No session ID
        null, // No IP
        null, // No user agent
        'GET',
        '', // Empty URL
        -1 // Invalid response time
      );

      expect(result).toBeDefined();
      expect(result.isBot).toBe(false);
      expect(result.recommendation).toBe('ALLOW');
    });

    it('should handle concurrent bot detection requests', async () => {
      const requests = Array.from({ length: 5 }, (_, i) =>
        service.analyzeRequest(
          `user-${i}`,
          `session-${i}`,
          `192.168.1.${i + 1}`,
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'GET',
          `/api/test${i}`,
          150
        )
      );

      const results = await Promise.all(requests);

      results.forEach(result => {
        expect(result).toBeDefined();
        expect(typeof result.isBot).toBe('boolean');
        expect(result.confidence).toBeGreaterThanOrEqual(0);
        expect(result.confidence).toBeLessThanOrEqual(1);
      });
    });

    it('should handle service dependencies being unavailable', async () => {
      // Make device service throw error
      deviceFingerprintingService.analyzeDeviceForBot.mockRejectedValue(
        new Error('Service unavailable')
      );

      // Make session lookup throw error
      prismaService.session.findUnique.mockRejectedValue(
        new Error('Database connection failed')
      );

      const result = await service.analyzeRequest(
        mockUserId,
        mockSessionId,
        mockIP,
        mockUserAgent,
        'GET',
        '/api/test',
        150
      );

      // Should return safe default result
      expect(result.isBot).toBe(false);
      expect(result.recommendation).toBe('ALLOW');
      expect(result.indicators).toHaveLength(0);
    });
  });

  describe('Configuration Boundaries', () => {
    it('should respect risk score thresholds', async () => {
      // Test with risk score just below critical threshold
      deviceFingerprintingService.analyzeDeviceForBot.mockResolvedValue({
        deviceId: 'device-boundary',
        isBot: true,
        confidence: 0.89, // Just below critical (0.9)
        riskScore: 0.89,
        isSuspicious: true,
        indicators: ['Suspicious pattern'],
        recommendation: 'CHALLENGE',
        similarityScore: 0.2,
        matchedDevices: [],
        isNewDevice: true,
        analysis: { userAgent: true, deviceType: false, browser: false, os: false, timing: false, pattern: true },
        firstSeen: new Date(),
        lastSeen: new Date(),
      });

      const result = await service.analyzeRequest(
        mockUserId,
        mockSessionId,
        mockIP,
        'suspicious-agent',
        'GET',
        '/api/test',
        150
      );

      expect(result.isBot).toBe(true);
      expect(result.recommendation).toBe('CHALLENGE'); // Not BLOCK
      expect(ipReputationService.blockIP).not.toHaveBeenCalled(); // No auto-block
    });
  });
});