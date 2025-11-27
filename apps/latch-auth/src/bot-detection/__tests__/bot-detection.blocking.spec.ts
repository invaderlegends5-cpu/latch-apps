// bot-detection.blocking.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { BotDetectionService } from '../bot-detection.service';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';
import { EventLogService } from '@/events/event.service';
import { PrismaService } from '@/prisma/prisma.service';
import { BehavioralAnalysisService } from '@/behavioral-analysis/behavioral-analysis.service';
import { RedisService } from '@/redis/redis.service';
import { ConfigService } from '@nestjs/config';
import { DeviceFingerprintingService } from '@/device-fingerprinting/device-fingerprinting.service';

describe('BotDetectionService - Blocking', () => {
  let service: BotDetectionService;
  let ipReputationService: jest.Mocked<IPReputationService>;
  let eventLogService: jest.Mocked<EventLogService>;
  let deviceFingerprintingService: jest.Mocked<DeviceFingerprintingService>;
  let prismaService: jest.Mocked<PrismaService>; // Add PrismaService

  const mockIP = '192.168.1.1';
  const mockIndicators = [
    'Known bot user agent pattern detected: Googlebot',
    'Unusually fast response time: 5ms'
  ];

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        BotDetectionService,
        {
          provide: IPReputationService,
          useValue: {
            isIPBlocked: jest.fn(),
            blockIP: jest.fn(),
          },
        },
        {
          provide: EventLogService,
          useValue: {
            logEvent: jest.fn(),
          },
        },
        // --- CRITICAL: Mock PrismaService properly ---
        {
          provide: PrismaService,
          useValue: {
            session: {
              findUnique: jest.fn(), // Mock the findUnique method
            },
            // Add other Prisma models/services if analyzeRequest uses them
          },
        },
        // --- End of critical addition ---
        { provide: BehavioralAnalysisService, useValue: {} },
        { provide: RedisService, useValue: {} },
        {
          provide: DeviceFingerprintingService,
          useValue: {
            analyzeDeviceForBot: jest.fn(), // Add the necessary mock
            // Add other methods if the tests call them
          },
        },
        { provide: ConfigService, useValue: {} },
      ],
    }).compile();

    service = module.get<BotDetectionService>(BotDetectionService);
    ipReputationService = module.get(IPReputationService);
    eventLogService = module.get(EventLogService);
    deviceFingerprintingService = module.get(DeviceFingerprintingService);
    // --- CRITICAL: Get the PrismaService instance ---
    prismaService = module.get(PrismaService);
    // --- End of critical addition ---
  });

  describe('High-Risk IP Handling', () => {
    it('should block IP when risk score exceeds threshold', async () => {
      const highRiskScore = 0.95;
      ipReputationService.isIPBlocked.mockResolvedValue(false);

      await service['handleHighRiskIP'](mockIP, highRiskScore, mockIndicators);

      expect(ipReputationService.blockIP).toHaveBeenCalledWith(
        mockIP,
        expect.stringContaining('High bot risk detected'),
        expect.any(Number) // autoBlockDuration
      );

      expect(eventLogService.logEvent).toHaveBeenCalledWith(
        'SECURITY_CSRF_ERROR',
        expect.objectContaining({
          metadata: expect.objectContaining({
            reason: 'auto_block_high_risk_bot_ip',
            ipAddress: mockIP,
            riskScore: highRiskScore,
          }),
        })
      );
    });

    it('should not block already blocked IP', async () => {
      const highRiskScore = 0.95;
      ipReputationService.isIPBlocked.mockResolvedValue(true);

      await service['handleHighRiskIP'](mockIP, highRiskScore, mockIndicators);

      expect(ipReputationService.blockIP).not.toHaveBeenCalled();

      // Should log continued suspicious activity
      expect(eventLogService.logEvent).toHaveBeenCalledWith(
        'SECURITY_CSRF_ERROR',
        expect.objectContaining({
          metadata: expect.objectContaining({
            reason: 'continued_bot_activity_on_blocked_ip',
          }),
        })
      );
    });

 // Inside the test file: bot-detection.blocking.spec.ts
// In the 'High-Risk IP Handling' describe block:

it('should handle blocking errors gracefully (by escalating)', async () => {
    const highRiskScore = 0.95;
    ipReputationService.isIPBlocked.mockResolvedValue(false);
    // Mock blockIP to reject, simulating a failure in the blocking service
    ipReputationService.blockIP.mockRejectedValue(new Error('Blocking service unavailable'));

    // Expect the promise to be rejected because handleHighRiskIP re-throws the error
    // This is the core hardening behavior being tested here.
    await expect(
      service['handleHighRiskIP'](mockIP, highRiskScore, mockIndicators)
    ).rejects.toThrow('Blocking service unavailable'); // Or expect.any(Error)

    // No further assertion needed here regarding internal logging within handleHighRiskIP.
    // The fact that the rejection occurs confirms the hardening.
    // Verification of *how* the error is handled after escalation (logging via eventLogService,
    // Sentry call, default result return) is the responsibility of the outer error handling test
    // suite (e.g., the test in bot-detection.service.spec.ts).
  });

    it('should include all indicators in block reason', async () => {
      const highRiskScore = 0.92;
      const indicators = [
        'Known bot user agent: Googlebot',
        'Very fast response time: 8ms',
        'Suspicious URL pattern: /admin'
      ];

      ipReputationService.isIPBlocked.mockResolvedValue(false);

      await service['handleHighRiskIP'](mockIP, highRiskScore, indicators);

      expect(ipReputationService.blockIP).toHaveBeenCalledWith(
        mockIP,
        expect.stringContaining('Known bot user agent: Googlebot'),
        expect.any(Number)
      );

      expect(ipReputationService.blockIP).toHaveBeenCalledWith(
        mockIP,
        expect.stringContaining('Very fast response time: 8ms'),
        expect.any(Number)
      );

      expect(ipReputationService.blockIP).toHaveBeenCalledWith(
        mockIP,
        expect.stringContaining('Suspicious URL pattern: /admin'),
        expect.any(Number)
      );
    });
  });

  describe('Auto-Blocking Integration', () => {
    // Mock the session data for analyzeSessionBehavior
    beforeEach(() => {
        prismaService.session.findUnique.mockResolvedValue({
          id: 'session-456',
          userId: 'user-123',
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
    });

    it('should trigger auto-blocking during request analysis', async () => {
      // Mock all analysis methods to return high-risk results
      ipReputationService.isIPBlocked.mockResolvedValue(false);
      deviceFingerprintingService.analyzeDeviceForBot.mockResolvedValue({
        deviceId: 'device-bot',
        isBot: true,
        confidence: 0.95,
        riskScore: 0.95,
        isSuspicious: true,
        indicators: ['Known bot signature'],
        recommendation: 'BLOCK',
        similarityScore: 0,
        matchedDevices: [],
        isNewDevice: true,
        analysis: { userAgent: true, deviceType: true, browser: true, os: true, timing: true, pattern: true },
        firstSeen: new Date(),
        lastSeen: new Date(),
      });

      const result = await service.analyzeRequest(
        'user-123',
        'session-456',
        mockIP,
        'HeadlessChrome',
        'GET',
        '/api/test',
        5
      );

      expect(result.isBot).toBe(true);
      expect(result.recommendation).toBe('BLOCK');
      expect(ipReputationService.blockIP).toHaveBeenCalled();
    });

    it('should not auto-block when risk score is below threshold', async () => {
      // Mock analysis to return medium risk
      deviceFingerprintingService.analyzeDeviceForBot.mockResolvedValue({
        deviceId: 'device-normal',
        isBot: false,
        confidence: 0.5,
        riskScore: 0.5,
        isSuspicious: false,
        indicators: [],
        recommendation: 'ALLOW',
        similarityScore: 0.8,
        matchedDevices: ['device-existing'],
        isNewDevice: false,
        analysis: { userAgent: false, deviceType: false, browser: false, os: false, timing: false, pattern: false },
        firstSeen: new Date('2023-01-01'),
        lastSeen: new Date(),
      });

      const result = await service.analyzeRequest(
        'user-123',
        'session-456',
        mockIP,
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'GET',
        '/api/test',
        150
      );

      expect(result.isBot).toBe(false);
      expect(result.recommendation).toBe('ALLOW');
      expect(ipReputationService.blockIP).not.toHaveBeenCalled();
    });
  });
});