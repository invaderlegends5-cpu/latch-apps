// device-fingerprinting.analysis.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { DeviceFingerprintingService } from '../device-fingerprinting.service';
import { DeviceFingerprint } from '../types/device.types';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { SecurityMonitoringService } from '@/security/security-monitor.service';
import { ConfigService } from '@nestjs/config';

describe('DeviceFingerprintingService - Analysis Methods', () => {
  let service: DeviceFingerprintingService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        DeviceFingerprintingService,
        { provide: PrismaService, useValue: {} },
        { provide: EventLogService, useValue: {} },
        { provide: SecurityMonitoringService, useValue: {} },
        { provide: ConfigService, useValue: {} },
      ],
    }).compile();

    service = module.get<DeviceFingerprintingService>(DeviceFingerprintingService);
  });

  describe('Fingerprint Comparison', () => {
    it('should detect different devices by IP address', () => {
      const fp1: DeviceFingerprint = {
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ipAddress: '192.168.1.1',
        os: 'Windows',
        browser: 'Chrome',
        deviceType: 'desktop',
      };

      const fp2: DeviceFingerprint = {
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ipAddress: '192.168.1.2', // Different IP
        os: 'Windows',
        browser: 'Chrome',
        deviceType: 'desktop',
      };

      const isDifferent = service['areFingerprintsDifferent'](fp1, fp2);

      expect(isDifferent).toBe(true);
    });

    it('should detect different devices by OS', () => {
      const fp1: DeviceFingerprint = {
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ipAddress: '192.168.1.1',
        os: 'Windows',
        browser: 'Chrome',
        deviceType: 'desktop',
      };

      const fp2: DeviceFingerprint = {
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
        ipAddress: '192.168.1.1',
        os: 'macOS', // Different OS
        browser: 'Safari',
        deviceType: 'desktop',
      };

      const isDifferent = service['areFingerprintsDifferent'](fp1, fp2);

      expect(isDifferent).toBe(true);
    });

    it('should detect different devices by browser on same OS', () => {
      const fp1: DeviceFingerprint = {
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ipAddress: '192.168.1.1',
        os: 'Windows',
        browser: 'Chrome',
        deviceType: 'desktop',
      };

      const fp2: DeviceFingerprint = {
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ipAddress: '192.168.1.1',
        os: 'Windows',
        browser: 'Firefox', // Different browser
        deviceType: 'desktop',
      };

      const isDifferent = service['areFingerprintsDifferent'](fp1, fp2);

      expect(isDifferent).toBe(true);
    });

    it('should detect different devices by device type', () => {
      const fp1: DeviceFingerprint = {
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ipAddress: '192.168.1.1',
        os: 'Windows',
        browser: 'Chrome',
        deviceType: 'desktop',
      };

      const fp2: DeviceFingerprint = {
        userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
        ipAddress: '192.168.1.1',
        os: 'iOS',
        browser: 'Safari',
        deviceType: 'mobile', // Different device type
      };

      const isDifferent = service['areFingerprintsDifferent'](fp1, fp2);

      expect(isDifferent).toBe(true);
    });

    it('should not detect difference for identical fingerprints', () => {
      const fp1: DeviceFingerprint = {
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ipAddress: '192.168.1.1',
        os: 'Windows',
        browser: 'Chrome',
        deviceType: 'desktop',
      };

      const fp2: DeviceFingerprint = {
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ipAddress: '192.168.1.1',
        os: 'Windows',
        browser: 'Chrome',
        deviceType: 'desktop',
      };

      const isDifferent = service['areFingerprintsDifferent'](fp1, fp2);

      expect(isDifferent).toBe(false);
    });

    it('should handle fingerprints with missing data', () => {
      const fp1: DeviceFingerprint = {
        userAgent: null,
        ipAddress: '192.168.1.1',
      };

      const fp2: DeviceFingerprint = {
        userAgent: 'test-agent',
        ipAddress: null,
      };

      const isDifferent = service['areFingerprintsDifferent'](fp1, fp2);

      // Should still work without crashing
      expect(typeof isDifferent).toBe('boolean');
    });
  });

  describe('Fingerprint Extraction', () => {
    it('should extract fingerprint from session data', () => {
      const session = {
        id: 'session-123',
        userId: 'user-123',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        ipAddress: '192.168.1.1',
        // Other session properties...
        tenantId: 'tenant-123',
        refreshHash: 'hash',
        createdAt: new Date(),
        lastActiveAt: new Date(),
        expiresAt: new Date(),
        revoked: false,
        csrfToken: 'csrf',
      };

      const fingerprint = service['extractFingerprintFromSession'](session);

      expect(fingerprint.userAgent).toBe(session.userAgent);
      expect(fingerprint.ipAddress).toBe(session.ipAddress);
      expect(fingerprint.os).toBe('Windows');
      expect(fingerprint.browser).toBe('Chrome');
      expect(fingerprint.deviceType).toBe('desktop');
    });

    it('should handle session with null user agent and IP', () => {
      const session = {
        id: 'session-123',
        userId: 'user-123',
        userAgent: null,
        ipAddress: null,
        tenantId: 'tenant-123',
        refreshHash: 'hash',
        createdAt: new Date(),
        lastActiveAt: new Date(),
        expiresAt: new Date(),
        revoked: false,
        csrfToken: 'csrf',
      };

      const fingerprint = service['extractFingerprintFromSession'](session);

      expect(fingerprint.userAgent).toBeNull();
      expect(fingerprint.ipAddress).toBeNull();
      expect(fingerprint.os).toBeUndefined();
      expect(fingerprint.browser).toBeUndefined();
      expect(fingerprint.deviceType).toBeUndefined();
    });
  });

  describe('Severity Mapping', () => {
    it('should map severity to event severity correctly', () => {
      expect(service['mapSeverityToEvent']('LOW')).toBe('INFO');
      expect(service['mapSeverityToEvent']('MEDIUM')).toBe('SECURITY');
      expect(service['mapSeverityToEvent']('HIGH')).toBe('SECURITY');
      expect(service['mapSeverityToEvent']('CRITICAL')).toBe('CRITICAL');
    });

    it('should handle unknown severity', () => {
      expect(service['mapSeverityToEvent']('UNKNOWN' as any)).toBe('INFO');
    });
  });
});