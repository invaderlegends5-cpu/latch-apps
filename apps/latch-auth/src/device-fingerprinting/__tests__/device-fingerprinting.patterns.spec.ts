// device-fingerprinting.patterns.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { DeviceFingerprintingService } from '../device-fingerprinting.service';
import { PrismaService } from '@/prisma/prisma.service';
import { DeviceFingerprint, DeviceSessionPattern } from '../types/device.types';
import { EventLogService } from '@/events/event.service';
import { SecurityMonitoringService } from '@/security/security-monitor.service';
import { ConfigService } from '@nestjs/config';

describe('DeviceFingerprintingService - Pattern Tracking', () => {
  let service: DeviceFingerprintingService;
  let prismaService: jest.Mocked<PrismaService>;

  const mockUserId = 'user-123';
  const mockSessionId = 'session-456';
  const mockIP = '192.168.1.1';
  const mockUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';

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
        { provide: EventLogService, useValue: {} },
        { provide: SecurityMonitoringService, useValue: {} },
        { provide: ConfigService, useValue: {} },
      ],
    }).compile();

    service = module.get<DeviceFingerprintingService>(DeviceFingerprintingService);
    prismaService = module.get(PrismaService);
  });

  describe('Pattern Management', () => {
    it('should create new device pattern for new fingerprint', async () => {
      const fingerprint: DeviceFingerprint = {
        userAgent: mockUserAgent,
        ipAddress: mockIP,
        os: 'Windows',
        browser: 'Chrome',
        deviceType: 'desktop',
      };

      await service['updateDevicePattern'](mockUserId, mockSessionId, fingerprint);

      const patternKey = service['getDevicePatternKey'](mockUserId, fingerprint);
      const pattern = service['devicePatterns'].get(patternKey);

      expect(pattern).toBeDefined();
      expect(pattern?.userId).toBe(mockUserId);
      expect(pattern?.fingerprint).toEqual(fingerprint);
      expect(pattern?.sessionIds).toEqual([mockSessionId]);
      expect(pattern?.firstSeen).toBeInstanceOf(Date);
      expect(pattern?.lastSeen).toBeInstanceOf(Date);
      expect(pattern?.active).toBe(true);
    });

    it('should update existing device pattern with new session', async () => {
      const fingerprint: DeviceFingerprint = {
        userAgent: mockUserAgent,
        ipAddress: mockIP,
        os: 'Windows',
        browser: 'Chrome',
        deviceType: 'desktop',
      };

      // First session
      await service['updateDevicePattern'](mockUserId, 'session-1', fingerprint);
      
      // Second session with same fingerprint
      await service['updateDevicePattern'](mockUserId, 'session-2', fingerprint);

      const patternKey = service['getDevicePatternKey'](mockUserId, fingerprint);
      const pattern = service['devicePatterns'].get(patternKey);

      expect(pattern?.sessionIds).toContain('session-1');
      expect(pattern?.sessionIds).toContain('session-2');
      expect(pattern?.sessionIds).toHaveLength(2);
      expect(pattern?.lastSeen.getTime()).toBeGreaterThanOrEqual(pattern?.firstSeen.getTime() || 0);
    });

    it('should not duplicate session IDs in pattern', async () => {
      const fingerprint: DeviceFingerprint = {
        userAgent: mockUserAgent,
        ipAddress: mockIP,
        os: 'Windows',
        browser: 'Chrome',
        deviceType: 'desktop',
      };

      // Add same session multiple times
      await service['updateDevicePattern'](mockUserId, mockSessionId, fingerprint);
      await service['updateDevicePattern'](mockUserId, mockSessionId, fingerprint);
      await service['updateDevicePattern'](mockUserId, mockSessionId, fingerprint);

      const patternKey = service['getDevicePatternKey'](mockUserId, fingerprint);
      const pattern = service['devicePatterns'].get(patternKey);

      expect(pattern?.sessionIds).toEqual([mockSessionId]); // Should not duplicate
    });

    it('should track recent device usage', async () => {
      const fingerprint: DeviceFingerprint = {
        userAgent: mockUserAgent,
        ipAddress: mockIP,
        os: 'Windows',
        browser: 'Chrome',
        deviceType: 'desktop',
      };

      await service['updateDevicePattern'](mockUserId, mockSessionId, fingerprint);

      const deviceKey = `${mockUserId}:${mockIP}:${mockUserAgent}`;
      const timestamps = service['recentDevices'].get(deviceKey);

      expect(timestamps).toBeDefined();
      expect(timestamps).toHaveLength(1);
      expect(timestamps?.[0]).toBeInstanceOf(Date);
    });
  });

  describe('Pattern Key Generation', () => {
    it('should generate consistent pattern keys', () => {
      const fingerprint: DeviceFingerprint = {
        userAgent: mockUserAgent,
        ipAddress: mockIP,
        os: 'Windows',
        browser: 'Chrome',
        deviceType: 'desktop',
      };

      const key1 = service['getDevicePatternKey'](mockUserId, fingerprint);
      const key2 = service['getDevicePatternKey'](mockUserId, fingerprint);

      expect(key1).toBe(key2);
      expect(key1).toBe(`${mockUserId}:${mockIP}:${mockUserAgent}`);
    });

    it('should handle null user agent and IP in pattern key', () => {
      const fingerprint: DeviceFingerprint = {
        userAgent: null,
        ipAddress: null,
      };

      const key = service['getDevicePatternKey'](mockUserId, fingerprint);

      expect(key).toBe(`${mockUserId}:unknown:unknown`);
    });

    it('should handle partial fingerprint data', () => {
      const fingerprint: DeviceFingerprint = {
        userAgent: mockUserAgent,
        ipAddress: null, // Missing IP
      };

      const key = service['getDevicePatternKey'](mockUserId, fingerprint);

      expect(key).toBe(`${mockUserId}:unknown:${mockUserAgent}`);
    });
  });

  describe('Load Recent Patterns', () => {
    it('should load recent patterns from database', async () => {
      const mockSessions = [
        {
          id: 'session-1',
          userId: 'user-1',
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
          ipAddress: '192.168.1.1',
          createdAt: new Date(),
          lastActiveAt: new Date(),
          expiresAt: new Date(),
          revoked: false,
          tenantId: 'tenant-1',
          refreshHash: 'hash1',
          csrfToken: 'csrf1',
        },
        {
          id: 'session-2',
          userId: 'user-2',
          userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15A372 Safari/604.1',
          ipAddress: '192.168.1.2',
          createdAt: new Date(),
          lastActiveAt: new Date(),
          expiresAt: new Date(),
          revoked: false,
          tenantId: 'tenant-2',
          refreshHash: 'hash2',
          csrfToken: 'csrf2',
        },
      ];

      prismaService.session.findMany.mockResolvedValue(mockSessions);

      await service['loadRecentPatterns']();

      // Should create patterns for both sessions
      expect(service['devicePatterns'].size).toBe(2);
      
      // Check first pattern
      const patternKey1 = `${mockSessions[0].userId}:${mockSessions[0].ipAddress}:${mockSessions[0].userAgent}`;
      const pattern1 = service['devicePatterns'].get(patternKey1);
      expect(pattern1?.sessionIds).toContain('session-1');
      expect(pattern1?.fingerprint.os).toBe('Windows');
      expect(pattern1?.fingerprint.browser).toBe('Chrome');
      expect(pattern1?.fingerprint.deviceType).toBe('desktop');

      // Check second pattern
      const patternKey2 = `${mockSessions[1].userId}:${mockSessions[1].ipAddress}:${mockSessions[1].userAgent}`;
      const pattern2 = service['devicePatterns'].get(patternKey2);
      expect(pattern2?.sessionIds).toContain('session-2');
      expect(pattern2?.fingerprint.os).toBe('iOS');
      expect(pattern2?.fingerprint.deviceType).toBe('mobile');
    });

    it('should handle sessions without user agent or IP', async () => {
      const mockSessions = [
        {
          id: 'session-1',
          userId: 'user-1',
          userAgent: null, // No user agent
          ipAddress: '192.168.1.1',
          createdAt: new Date(),
          lastActiveAt: new Date(),
          expiresAt: new Date(),
          revoked: false,
          tenantId: 'tenant-1',
          refreshHash: 'hash1',
          csrfToken: 'csrf1',
        },
        {
          id: 'session-2',
          userId: 'user-2',
          userAgent: 'test-agent',
          ipAddress: null, // No IP
          createdAt: new Date(),
          lastActiveAt: new Date(),
          expiresAt: new Date(),
          revoked: false,
          tenantId: 'tenant-2',
          refreshHash: 'hash2',
          csrfToken: 'csrf2',
        },
      ];

      prismaService.session.findMany.mockResolvedValue(mockSessions);

      await service['loadRecentPatterns']();

      // Should still create patterns for sessions with partial data
      expect(service['devicePatterns'].size).toBe(2);
    });

    it('should handle database errors gracefully', async () => {
      prismaService.session.findMany.mockRejectedValue(new Error('Database connection failed'));

      await expect(service['loadRecentPatterns']()).resolves.not.toThrow();
      
      // Should not create any patterns on error
      expect(service['devicePatterns'].size).toBe(0);
    });
  });

  describe('Device ID Generation', () => {
    it('should generate consistent device IDs for same fingerprint', () => {
      const fingerprint: DeviceFingerprint = {
        userAgent: mockUserAgent,
        ipAddress: mockIP,
        os: 'Windows',
        browser: 'Chrome',
        deviceType: 'desktop',
      };

      const deviceId1 = service['generateDeviceId'](fingerprint);
      const deviceId2 = service['generateDeviceId'](fingerprint);

      expect(deviceId1).toBe(deviceId2);
      expect(deviceId1).toMatch(/^device-[a-z0-9]+$/);
    });

    it('should generate different device IDs for different fingerprints', () => {
      const fingerprint1: DeviceFingerprint = {
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ipAddress: '192.168.1.1',
        os: 'Windows',
        browser: 'Chrome',
        deviceType: 'desktop',
      };

      const fingerprint2: DeviceFingerprint = {
        userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
        ipAddress: '192.168.1.1',
        os: 'iOS',
        browser: 'Safari',
        deviceType: 'mobile',
      };

      const deviceId1 = service['generateDeviceId'](fingerprint1);
      const deviceId2 = service['generateDeviceId'](fingerprint2);

      expect(deviceId1).not.toBe(deviceId2);
    });

    it('should handle fingerprints with null values', () => {
      const fingerprint: DeviceFingerprint = {
        userAgent: null,
        ipAddress: null,
        os: undefined,
        browser: undefined,
        deviceType: undefined,
      };

      const deviceId = service['generateDeviceId'](fingerprint);

      expect(deviceId).toBeDefined();
      expect(deviceId).toMatch(/^device-[a-z0-9]+$/);
    });
  });
});