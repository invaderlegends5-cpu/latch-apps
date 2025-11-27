// device-fingerprinting.reuse-detection.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { DeviceFingerprintingService } from '../device-fingerprinting.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { SecurityMonitoringService } from '@/security/security-monitor.service';
import { ConfigService } from '@nestjs/config';

describe('DeviceFingerprintingService - Reuse Detection', () => {
  let service: DeviceFingerprintingService;
  let prismaService: jest.Mocked<PrismaService>;
  let eventLogService: jest.Mocked<EventLogService>;
  let securityMonitorService: jest.Mocked<SecurityMonitoringService>;

  const mockUserId = 'user-123';
  const mockCurrentSessionId = 'session-current';
  const mockExistingSessionId = 'session-existing';

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        DeviceFingerprintingService,
        {
          provide: PrismaService,
          useValue: {
            session: {
              findMany: jest.fn(),
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
  });

  describe('Device Reuse Detection', () => {
    it('should detect device reuse with different IP addresses', async () => {
      const currentFingerprint = {
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ipAddress: '192.168.1.100',
        os: 'Windows',
        browser: 'Chrome',
        deviceType: 'desktop',
      };

      const existingFingerprint = {
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        ipAddress: '192.168.1.200', // Different IP
        os: 'Windows',
        browser: 'Chrome',
        deviceType: 'desktop',
      };

      prismaService.session.findMany.mockResolvedValue([
        {
          id: mockExistingSessionId,
          userId: mockUserId,
          tenantId: 'tenant-123',
          refreshHash: 'hash',
          userAgent: existingFingerprint.userAgent,
          ipAddress: existingFingerprint.ipAddress,
          createdAt: new Date(),
          lastActiveAt: new Date(),
          expiresAt: new Date(Date.now() + 3600000),
          revoked: false,
          csrfToken: 'csrf-token',
          RefreshToken: [],
        },
      ]);

      await service['checkDeviceReuse'](mockUserId, mockCurrentSessionId, currentFingerprint as any);

      expect(eventLogService.logEvent).toHaveBeenCalledWith(
        'TOKEN_REUSE',
        expect.objectContaining({
          userId: mockUserId,
          metadata: expect.objectContaining({
            reason: 'device_reuse_detected',
            severity: 'MEDIUM', // IP difference only = MEDIUM
          }),
        })
      );
    });

    it('should detect device reuse with different OS', async () => {
      const currentFingerprint = {
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ipAddress: '192.168.1.1',
        os: 'Windows',
        browser: 'Chrome',
        deviceType: 'desktop',
      };

      const existingFingerprint = {
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
        ipAddress: '192.168.1.1',
        os: 'macOS', // Different OS
        browser: 'Safari',
        deviceType: 'desktop',
      };

      prismaService.session.findMany.mockResolvedValue([
        {
          id: mockExistingSessionId,
          userId: mockUserId,
          tenantId: 'tenant-123',
          refreshHash: 'hash',
          userAgent: existingFingerprint.userAgent,
          ipAddress: existingFingerprint.ipAddress,
          createdAt: new Date(),
          lastActiveAt: new Date(),
          expiresAt: new Date(Date.now() + 3600000),
          revoked: false,
          csrfToken: 'csrf-token',
          RefreshToken: [],
        },
      ]);

      await service['checkDeviceReuse'](mockUserId, mockCurrentSessionId, currentFingerprint as any);

      expect(eventLogService.logEvent).toHaveBeenCalled();
    });

    it('should not detect reuse for identical fingerprints', async () => {
      const fingerprint = {
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ipAddress: '192.168.1.1',
        os: 'Windows',
        browser: 'Chrome',
        deviceType: 'desktop',
      };

      prismaService.session.findMany.mockResolvedValue([
        {
          id: mockExistingSessionId,
          userId: mockUserId,
          tenantId: 'tenant-123',
          refreshHash: 'hash',
          userAgent: fingerprint.userAgent,
          ipAddress: fingerprint.ipAddress,
          createdAt: new Date(),
          lastActiveAt: new Date(),
          expiresAt: new Date(Date.now() + 3600000),
          revoked: false,
          csrfToken: 'csrf-token',
          RefreshToken: [],
        },
      ]);

      await service['checkDeviceReuse'](mockUserId, mockCurrentSessionId, fingerprint as any);

      // Should not log reuse event for identical fingerprints
      expect(eventLogService.logEvent).not.toHaveBeenCalledWith(
        'TOKEN_REUSE',
        expect.anything()
      );
    });

    it('should skip current session when checking reuse', async () => {
      const fingerprint = {
        userAgent: 'test-agent',
        ipAddress: '192.168.1.1',
        os: 'Windows',
        browser: 'Chrome',
        deviceType: 'desktop',
      };

      prismaService.session.findMany.mockResolvedValue([
        {
          id: mockCurrentSessionId, // Same as current session
          userId: mockUserId,
          tenantId: 'tenant-123',
          refreshHash: 'hash',
          userAgent: fingerprint.userAgent,
          ipAddress: fingerprint.ipAddress,
          createdAt: new Date(),
          lastActiveAt: new Date(),
          expiresAt: new Date(Date.now() + 3600000),
          revoked: false,
          csrfToken: 'csrf-token',
          RefreshToken: [],
        },
      ]);

      await service['checkDeviceReuse'](mockUserId, mockCurrentSessionId, fingerprint as any);

      // Should not detect reuse with itself
      expect(eventLogService.logEvent).not.toHaveBeenCalled();
    });
  });

  describe('Reuse Severity Calculation', () => {
    it('should calculate CRITICAL severity for 3+ differences', () => {
      const fp1 = { ipAddress: '1.1.1.1', os: 'Windows', browser: 'Chrome', deviceType: 'desktop' };
      const fp2 = { ipAddress: '2.2.2.2', os: 'macOS', browser: 'Safari', deviceType: 'mobile' };

      const severity = service['calculateReuseSeverity'](fp1 as any, fp2 as any);
      expect(severity).toBe('CRITICAL');
    });

    it('should calculate HIGH severity for 2 differences', () => {
      const fp1 = { ipAddress: '1.1.1.1', os: 'Windows', browser: 'Chrome', deviceType: 'desktop' };
      const fp2 = { ipAddress: '2.2.2.2', os: 'macOS', browser: 'Chrome', deviceType: 'desktop' };

      const severity = service['calculateReuseSeverity'](fp1 as any, fp2 as any);
      expect(severity).toBe('HIGH');
    });

    it('should calculate MEDIUM severity for 1 difference', () => {
      const fp1 = { ipAddress: '1.1.1.1', os: 'Windows', browser: 'Chrome', deviceType: 'desktop' };
      const fp2 = { ipAddress: '2.2.2.2', os: 'Windows', browser: 'Chrome', deviceType: 'desktop' };

      const severity = service['calculateReuseSeverity'](fp1 as any, fp2 as any);
      expect(severity).toBe('MEDIUM');
    });

    it('should calculate LOW severity for no differences', () => {
      const fp1 = { ipAddress: '1.1.1.1', os: 'Windows', browser: 'Chrome', deviceType: 'desktop' };
      const fp2 = { ipAddress: '1.1.1.1', os: 'Windows', browser: 'Chrome', deviceType: 'desktop' };

      const severity = service['calculateReuseSeverity'](fp1 as any, fp2 as any);
      expect(severity).toBe('LOW');
    });
  });

  describe('Reuse Reason Generation', () => {
    it('should generate correct reuse reasons', () => {
      const fp1 = { ipAddress: '1.1.1.1', os: 'Windows', browser: 'Chrome', deviceType: 'desktop' };
      const fp2 = { ipAddress: '2.2.2.2', os: 'macOS', browser: 'Safari', deviceType: 'mobile' };

      const reason = service['getReuseReason'](fp1 as any, fp2 as any);
      expect(reason).toBe('different IP addresses and different operating systems and different browsers and different device types');
    });

    it('should handle partial differences', () => {
      const fp1 = { ipAddress: '1.1.1.1', os: 'Windows', browser: 'Chrome', deviceType: 'desktop' };
      const fp2 = { ipAddress: '1.1.1.1', os: 'Windows', browser: 'Firefox', deviceType: 'desktop' };

      const reason = service['getReuseReason'](fp1 as any, fp2 as any);
      expect(reason).toBe('different browsers');
    });
  });
});