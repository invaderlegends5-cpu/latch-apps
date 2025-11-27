// device-fingerprinting.integration.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { DeviceFingerprintingService } from '../device-fingerprinting.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { SecurityMonitoringService } from '@/security/security-monitor.service';
import { DeviceAnalysisResult } from '../types/device.types';
import { ConfigService } from '@nestjs/config';

describe('DeviceFingerprintingService - Integration', () => {
  let service: DeviceFingerprintingService;
  let prismaService: jest.Mocked<PrismaService>;
  let eventLogService: jest.Mocked<EventLogService>;
  let securityMonitorService: jest.Mocked<SecurityMonitoringService>;

  const mockUserId = 'user-123';
  const mockSessionId = 'session-456';
  const mockIP = '192.168.1.1';

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
        { provide: ConfigService, useValue: {} },
      ],
    }).compile();

    service = module.get<DeviceFingerprintingService>(DeviceFingerprintingService);
    prismaService = module.get(PrismaService);
    eventLogService = module.get(EventLogService);
    securityMonitorService = module.get(SecurityMonitoringService);

    jest.clearAllMocks();
  });

  describe('End-to-End Device Fingerprinting', () => {
    it('should perform complete device fingerprinting workflow', async () => {
      // Mock recent sessions to simulate device reuse scenario
      prismaService.session.findMany.mockResolvedValue([
        {
          id: 'existing-session',
          userId: mockUserId,
          userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
          ipAddress: '192.168.1.100', // Different IP
          createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000), // 2 hours ago
          lastActiveAt: new Date(Date.now() - 30 * 60 * 1000), // 30 minutes ago
          expiresAt: new Date(Date.now() + 3600000),
          revoked: false,
          tenantId: 'tenant-123',
          refreshHash: 'hash',
          csrfToken: 'csrf',
          RefreshToken: [],
        },
      ]);

      await service.analyzeDeviceFingerprint(
        mockUserId,
        mockSessionId,
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', // Different device
        mockIP
      );

      // Should log device fingerprint
      expect(eventLogService.logEvent).toHaveBeenCalledWith(
        'LOGIN',
        expect.objectContaining({
          userId: mockUserId,
          metadata: expect.objectContaining({
            deviceFingerprint: expect.anything(),
          }),
        })
      );

      // Should detect device reuse and log security event
      expect(eventLogService.logEvent).toHaveBeenCalledWith(
        'TOKEN_REUSE',
        expect.objectContaining({
          userId: mockUserId,
          metadata: expect.objectContaining({
            reason: 'device_reuse_detected',
          }),
        })
      );

      // Should trigger security monitor
      expect(securityMonitorService.handleEvent).toHaveBeenCalled();

      // Should update device patterns
      const patternKey = `${mockUserId}:${mockIP}:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36`;
      expect(service['devicePatterns'].has(patternKey)).toBe(true);
    });

    it('should handle multiple device patterns for same user', async () => {
      const devices = [
        {
          sessionId: 'session-desktop',
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          ipAddress: '192.168.1.1',
        },
        {
          sessionId: 'session-mobile',
          userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
          ipAddress: '192.168.1.1',
        },
        {
          sessionId: 'session-tablet',
          userAgent: 'Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
          ipAddress: '192.168.1.2', // Different IP
        },
      ];

      for (const device of devices) {
        await service.analyzeDeviceFingerprint(
          mockUserId,
          device.sessionId,
          device.userAgent,
          device.ipAddress
        );
      }

      // Should create separate patterns for each device
      expect(service['devicePatterns'].size).toBe(3);

      // Should track all sessions in recent devices
      expect(service['recentDevices'].size).toBe(3);
    });

    it('should integrate bot detection with device fingerprinting', async () => {
      prismaService.session.findUnique.mockResolvedValue({
        id: mockSessionId,
        userId: mockUserId,
        userAgent: 'HeadlessChrome',
        ipAddress: mockIP,
        createdAt: new Date(),
        lastActiveAt: new Date(),
        expiresAt: new Date(Date.now() + 3600000),
        revoked: false,
        tenantId: 'tenant-123',
        refreshHash: 'hash',
        csrfToken: 'csrf',
      });

      const result: DeviceAnalysisResult = await service.analyzeDeviceForBot(
        mockUserId,
        mockSessionId,
        'Googlebot/2.1 (+http://www.google.com/bot.html)',
        mockIP,
        'GET',
        '/api/admin',
        5
      );

      expect(result.isBot).toBe(true);
      expect(result.analysis.userAgent).toBe(true);
      expect(result.analysis.timing).toBe(true);
      expect(result.analysis.pattern).toBe(true);
      expect(result.recommendation).toBe('BLOCK');

      // Should log bot detection event
      expect(eventLogService.logEvent).toHaveBeenCalledWith(
        'SECURITY_CSRF_ERROR',
        expect.objectContaining({
          metadata: expect.objectContaining({
            analysisType: 'DEVICE_BOT_DETECTION',
            isBot: true,
          }),
        })
      );
    });

    it('should handle normal user traffic without false positives', async () => {
      prismaService.session.findUnique.mockResolvedValue({
        id: mockSessionId,
        userId: mockUserId,
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ipAddress: mockIP,
        createdAt: new Date(),
        lastActiveAt: new Date(),
        expiresAt: new Date(Date.now() + 3600000),
        revoked: false,
        tenantId: 'tenant-123',
        refreshHash: 'hash',
        csrfToken: 'csrf',
      });

      const result = await service.analyzeDeviceForBot(
        mockUserId,
        mockSessionId,
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        mockIP,
        'GET',
        '/api/user/profile',
        150
      );

      expect(result.isBot).toBe(false);
      expect(result.recommendation).toBe('ALLOW');
      expect(result.analysis.userAgent).toBe(false);
      expect(result.analysis.timing).toBe(false);
      expect(result.analysis.pattern).toBe(false);

      // Should not log security event for normal traffic
      expect(eventLogService.logEvent).not.toHaveBeenCalledWith(
        'SECURITY_CSRF_ERROR',
        expect.objectContaining({
          metadata: expect.objectContaining({
            analysisType: 'DEVICE_BOT_DETECTION',
          }),
        })
      );
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle database failures gracefully', async () => {
      prismaService.session.findMany.mockRejectedValue(new Error('Database connection failed'));

      await expect(
        service.analyzeDeviceFingerprint(mockUserId, mockSessionId, 'test-agent', mockIP)
      ).resolves.not.toThrow();

      // Should still log the device fingerprint even if reuse check fails
      expect(eventLogService.logEvent).toHaveBeenCalledWith(
        'LOGIN',
        expect.anything()
      );
    });

    it('should handle concurrent device fingerprinting requests', async () => {
      const requests = Array.from({ length: 5 }, (_, i) =>
        service.analyzeDeviceFingerprint(
          `user-${i}`,
          `session-${i}`,
          `user-agent-${i}`,
          `192.168.1.${i + 1}`
        )
      );

      await Promise.all(requests);

      // Should handle all requests without conflicts
      expect(eventLogService.logEvent).toHaveBeenCalledTimes(5);
      expect(service['devicePatterns'].size).toBe(5);
    });

    it('should handle malformed user agents', async () => {
      const malformedUserAgents = [
        null,
        '',
        'Invalid User Agent String',
        '{invalid:json}',
        'a'.repeat(10000), // Very long string
      ];

      for (const userAgent of malformedUserAgents) {
        await expect(
          service.analyzeDeviceFingerprint(mockUserId, mockSessionId, userAgent, mockIP)
        ).resolves.not.toThrow();
      }
    });

    it('should handle mixed device analysis scenarios', async () => {
      // Test various combinations of device characteristics
      const testScenarios = [
        {
          userAgent: 'Googlebot/2.1',
          responseTime: 5,
          method: 'GET',
          url: '/api/data',
          expectedBot: true,
        },
        {
          userAgent: 'python-requests/2.28.1',
          responseTime: 100,
          method: 'GET',
          url: '/api/normal',
          expectedBot: true, // Non-browser client
        },
        {
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          responseTime: 150,
          method: 'GET',
          url: '/api/user/profile',
          expectedBot: false,
        },
        {
          userAgent: 'Mozilla/5.0',
          responseTime: 200,
          method: 'GET',
          url: '/api/test',
          expectedBot: true, // Minimal user agent
        },
      ];

      for (const scenario of testScenarios) {
        prismaService.session.findUnique.mockResolvedValue({
          id: mockSessionId,
          userId: mockUserId,
          userAgent: scenario.userAgent,
          ipAddress: mockIP,
          createdAt: new Date(),
          lastActiveAt: new Date(),
          expiresAt: new Date(Date.now() + 3600000),
          revoked: false,
          tenantId: 'tenant-123',
          refreshHash: 'hash',
          csrfToken: 'csrf',
        });

        const result = await service.analyzeDeviceForBot(
          mockUserId,
          mockSessionId,
          scenario.userAgent,
          mockIP,
          scenario.method,
          scenario.url,
          scenario.responseTime
        );

        expect(result.isBot).toBe(scenario.expectedBot);
      }
    });
  });

  describe('Configuration Boundaries', () => {
    it('should respect risk score thresholds and high-confidence indicators', async () => {
        // Test with risk score just below suspicious threshold
        prismaService.session.findUnique.mockResolvedValue({
          id: mockSessionId,
          userId: mockUserId,
          userAgent: 'suspicious-agent', // This is 15 chars, triggering minimal user agent detection
          ipAddress: mockIP,
          createdAt: new Date(),
          lastActiveAt: new Date(),
          expiresAt: new Date(Date.now() + 3600000),
          revoked: false,
          tenantId: 'tenant-123',
          refreshHash: 'hash',
          csrfToken: 'csrf',
        });
      
        const result = await service.analyzeDeviceForBot(
          mockUserId,
          mockSessionId,
          'suspicious-agent', 
          mockIP,
          'GET',
          '/api/test',
          100
        );
      
        // With current logic: isBot = riskScore > 0.7 OR userAgentAnalysis.confidence >= 0.7
        // 'suspicious-agent' triggers minimal user agent detection with confidence 0.7
        expect(result.isBot).toBe(true); // Because confidence >= 0.7
        expect(result.confidence).toBeGreaterThanOrEqual(0.7);
      });
  });
});