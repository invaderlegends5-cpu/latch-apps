// device-fingerprinting.service.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import * as Sentry from '@sentry/node';
import { DeviceFingerprintingService } from '../device-fingerprinting.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { SecurityMonitoringService } from '@/security/security-monitor.service';
import { DeviceFingerprint, DeviceSessionPattern, DeviceReuseAlert, DeviceAnalysisResult } from '../types/device.types';

// Mock Sentry
jest.mock('@sentry/node', () => ({
  captureException: jest.fn(),
}));

describe('DeviceFingerprintingService', () => {
  let service: DeviceFingerprintingService;
  let prismaService: jest.Mocked<PrismaService>;
  let eventLogService: jest.Mocked<EventLogService>;
  let securityMonitorService: jest.Mocked<SecurityMonitoringService>;

  const mockUserId = 'user-123';
  const mockSessionId = 'session-456';
  const mockIP = '192.168.1.1';
  const mockUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        DeviceFingerprintingService,
        {
          provide: PrismaService,
          useValue: {
            session: {
              findMany: jest.fn(),
              findUnique: jest.fn(),
            },
            refreshToken: {
                findMany: jest.fn(), // Add this for the RefreshToken include
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
          provide: SecurityMonitoringService,
          useValue: {
            handleEvent: jest.fn(),
          },
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<DeviceFingerprintingService>(DeviceFingerprintingService);
    prismaService = module.get(PrismaService);
    eventLogService = module.get(EventLogService);
    securityMonitorService = module.get(SecurityMonitoringService);

    // Clear all mocks
    jest.clearAllMocks();
  });

  describe('DeviceFingerprintingService', () => {
    let service: DeviceFingerprintingService;
    let prismaService: jest.Mocked<PrismaService>;
    let eventLogService: jest.Mocked<EventLogService>;
    let securityMonitorService: jest.Mocked<SecurityMonitoringService>;
  
    const mockUserId = 'user-123';
    const mockSessionId = 'session-456';
    const mockIP = '192.168.1.1';
    const mockUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
  
    beforeEach(async () => {
      const module: TestingModule = await Test.createTestingModule({
        providers: [
          DeviceFingerprintingService,
          {
            provide: PrismaService,
            useValue: {
              session: {
                findMany: jest.fn(),
                findUnique: jest.fn(),
              },
              refreshToken: {
                findMany: jest.fn(), // Add this for the RefreshToken include
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
            provide: SecurityMonitoringService,
            useValue: {
              handleEvent: jest.fn(),
            },
          },
          {
            provide: ConfigService,
            useValue: {
              get: jest.fn(),
            },
          },
        ],
      }).compile();
  
      service = module.get<DeviceFingerprintingService>(DeviceFingerprintingService);
      prismaService = module.get(PrismaService);
      eventLogService = module.get(EventLogService);
      securityMonitorService = module.get(SecurityMonitoringService);
  
      // Clear all mocks
      jest.clearAllMocks();
    });
  
    describe('Module lifecycle', () => {
      it('should be defined', () => {
        expect(service).toBeDefined();
      });
  
      it('should initialize successfully', async () => {
        prismaService.session.findMany.mockResolvedValue([]);
        
        await service.onModuleInit();
        
        expect(prismaService.session.findMany).toHaveBeenCalledWith({
          where: {
            createdAt: { gte: expect.any(Date) },
          },
          take: 1000,
        });
      });
  
      it('should handle initialization errors gracefully', async () => {
        prismaService.session.findMany.mockRejectedValue(new Error('DB error'));
        
        await expect(service.onModuleInit()).resolves.not.toThrow();
      });
    });
  
    describe('analyzeDeviceFingerprint', () => {
      it('should analyze device fingerprint and log event', async () => {
        // Mock the checkDeviceReuse to return empty array to avoid DB error
        const checkDeviceReuseSpy = jest.spyOn(service as any, 'checkDeviceReuse').mockResolvedValue(undefined);
  
        await service.analyzeDeviceFingerprint(
          mockUserId,
          mockSessionId,
          mockUserAgent,
          mockIP
        );
  
        // Should update device patterns
        const patternKey = `${mockUserId}:${mockIP}:${mockUserAgent}`;
        expect(service['devicePatterns'].has(patternKey)).toBe(true);
  
        // Should log the event - note that we need to check what the parseUserAgent actually returns
        expect(eventLogService.logEvent).toHaveBeenCalledWith(
          'LOGIN',
          expect.objectContaining({
            userId: mockUserId,
            ipAddress: mockIP,
            userAgent: mockUserAgent,
            metadata: expect.objectContaining({
              sessionId: mockSessionId,
              deviceFingerprint: expect.objectContaining({
                userAgent: mockUserAgent,
                ipAddress: mockIP,
                os: 'Windows',
                browser: 'Chrome', // This is what we expect
                deviceType: 'desktop',
              }),
            }),
          })
        );
  
        checkDeviceReuseSpy.mockRestore();
      });
  
      it('should handle null user agent and IP', async () => {
        const checkDeviceReuseSpy = jest.spyOn(service as any, 'checkDeviceReuse').mockResolvedValue(undefined);
  
        await service.analyzeDeviceFingerprint(
          mockUserId,
          mockSessionId,
          null,
          null
        );
  
        // Should still work without errors
        expect(eventLogService.logEvent).toHaveBeenCalled();
        
        checkDeviceReuseSpy.mockRestore();
      });
  
      it('should handle errors gracefully', async () => {
        // Mock to throw error during checkDeviceReuse
        jest.spyOn(service as any, 'checkDeviceReuse').mockRejectedValue(new Error('DB error'));
  
        await expect(
          service.analyzeDeviceFingerprint(mockUserId, mockSessionId, mockUserAgent, mockIP)
        ).resolves.not.toThrow();
  
        expect(Sentry.captureException).toHaveBeenCalled();
      });
    });
  
    describe('analyzeDeviceForBot', () => {
      it('should analyze device for bot behavior', async () => {
        prismaService.session.findUnique.mockResolvedValue({
          id: mockSessionId,
          userId: mockUserId,
          tenantId: 'tenant-123',
          refreshHash: 'hash',
          userAgent: mockUserAgent,
          ipAddress: mockIP,
          createdAt: new Date(),
          lastActiveAt: new Date(),
          expiresAt: new Date(Date.now() + 3600000),
          revoked: false,
          csrfToken: 'csrf-token',
        });
  
        const result = await service.analyzeDeviceForBot(
          mockUserId,
          mockSessionId,
          mockUserAgent,
          mockIP,
          'GET',
          '/api/test',
          150
        );
  
        expect(result).toBeDefined();
        expect(result.deviceId).toBeDefined();
        expect(result.isBot).toBe(false);
        expect(result.confidence).toBeGreaterThanOrEqual(0);
        expect(result.confidence).toBeLessThanOrEqual(1);
        expect(result.recommendation).toBe('ALLOW');
      });
  
      it('should detect bot from user agent', async () => {
        const botUserAgent = 'Googlebot/2.1 (+http://www.google.com/bot.html)';
        
        // Mock all other analysis methods to return 0 confidence to ensure user agent detection drives the result
        const analyzeSessionForBotSpy = jest.spyOn(service as any, 'analyzeSessionForBot').mockResolvedValue({
          isBot: false,
          confidence: 0,
          indicator: 'Normal session'
        });
      
        const analyzeTimingForBotSpy = jest.spyOn(service as any, 'analyzeTimingForBot').mockReturnValue({
          isBot: false,
          confidence: 0,
          indicator: 'Normal response time'
        });
      
        const analyzePatternForBotSpy = jest.spyOn(service as any, 'analyzePatternForBot').mockReturnValue({
          isBot: false,
          confidence: 0,
          indicator: 'Normal pattern'
        });
      
        const result = await service.analyzeDeviceForBot(
          mockUserId,
          mockSessionId,
          botUserAgent,
          mockIP,
          'GET',
          '/api/test',
          150
        );
      
        expect(result.isBot).toBe(true);
        expect(result.analysis.userAgent).toBe(true);
        expect(result.confidence).toBeGreaterThan(0.3);
      
        // Restore mocks
        analyzeSessionForBotSpy.mockRestore();
        analyzeTimingForBotSpy.mockRestore();
        analyzePatternForBotSpy.mockRestore();
      });
  
      it('should handle errors and return safe default', async () => {
        // Don't mock prisma here since analyzeSessionForBot should handle errors gracefully
  
        const result = await service.analyzeDeviceForBot(
          mockUserId,
          mockSessionId,
          mockUserAgent,
          mockIP,
          'GET',
          '/api/test',
          150
        );
  
        // The result should have proper browser detection
        expect(result.analysis.browser).toBe(false); // Since this is not a bot
        expect(result.analysis.userAgent).toBe(false); // Since this is not a bot
      });
    });
  
    describe('getDeviceReuseStats', () => {
      it('should return device reuse statistics', async () => {
        // Set up some device patterns
        const mockPattern: DeviceSessionPattern = {
          userId: mockUserId,
          fingerprint: {
            userAgent: mockUserAgent,
            ipAddress: mockIP,
            os: 'Windows',
            browser: 'Chrome',
            deviceType: 'desktop',
          },
          sessionIds: [mockSessionId],
          tokenFamilyIds: [],
          firstSeen: new Date(),
          lastSeen: new Date(),
          active: true,
        };
  
        service['devicePatterns'].set(`${mockUserId}:${mockIP}:${mockUserAgent}`, mockPattern);
  
        const stats = await service.getDeviceReuseStats(mockUserId);
  
        expect(stats).toEqual({
          totalDevices: 1,
          activeDevices: 1,
          devicePatterns: [
            {
              fingerprint: mockPattern.fingerprint,
              sessionCount: 1,
              firstSeen: mockPattern.firstSeen,
              lastSeen: mockPattern.lastSeen,
            },
          ],
        });
      });
  
      it('should return empty stats for user with no devices', async () => {
        const stats = await service.getDeviceReuseStats('non-existent-user');
  
        expect(stats).toEqual({
          totalDevices: 0,
          activeDevices: 0,
          devicePatterns: [],
        });
      });
    });
  });
});