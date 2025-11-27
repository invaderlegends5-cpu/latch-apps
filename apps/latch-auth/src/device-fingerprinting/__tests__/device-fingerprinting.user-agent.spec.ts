// device-fingerprinting.user-agent.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { DeviceFingerprintingService } from '../device-fingerprinting.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { SecurityMonitoringService } from '@/security/security-monitor.service';
import { ConfigService } from '@nestjs/config';

describe('DeviceFingerprintingService - User Agent Parsing', () => {
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

  describe('User Agent Parsing', () => {
    it('should parse Windows Chrome user agent correctly', () => {
      const userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36';
      
      const result = service['parseUserAgent'](userAgent);

      expect(result.os).toBe('Windows');
      expect(result.browser).toBe('Chrome');
      expect(result.deviceType).toBe('desktop');
    });

    it('should parse macOS Safari user agent correctly', () => {
      const userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15';
      
      const result = service['parseUserAgent'](userAgent);

      expect(result.os).toBe('macOS');
      expect(result.browser).toBe('Safari');
      expect(result.deviceType).toBe('desktop');
    });

    it('should parse Android Chrome user agent correctly', () => {
      const userAgent = 'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36';
      
      const result = service['parseUserAgent'](userAgent);

      expect(result.os).toBe('Android');
      expect(result.browser).toBe('Chrome');
      expect(result.deviceType).toBe('mobile');
    });

    it('should parse iOS Safari user agent correctly', () => {
      const userAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1';
      
      const result = service['parseUserAgent'](userAgent);

      expect(result.os).toBe('iOS');
      expect(result.browser).toBe('Safari');
      expect(result.deviceType).toBe('mobile');
    });

    it('should parse iPad user agent as tablet', () => {
      const userAgent = 'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1';
      
      const result = service['parseUserAgent'](userAgent);

      expect(result.os).toBe('iOS');
      expect(result.deviceType).toBe('tablet');
    });

    it('should parse Linux Firefox user agent correctly', () => {
      const userAgent = 'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0';
      
      const result = service['parseUserAgent'](userAgent);

      expect(result.os).toBe('Linux');
      expect(result.browser).toBe('Firefox');
      expect(result.deviceType).toBe('desktop');
    });

    it('should parse Edge browser correctly', () => {
      const userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59';
      
      const result = service['parseUserAgent'](userAgent);

      expect(result.browser).toBe('Edge');
    });

    it('should parse Opera browser correctly', () => {
      const userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 OPR/77.0.4054.90';
      
      const result = service['parseUserAgent'](userAgent);

      expect(result.browser).toBe('Opera');
    });

    it('should handle null user agent', () => {
      const result = service['parseUserAgent'](null);

      expect(result).toEqual({});
    });

    it('should handle empty user agent', () => {
      const result = service['parseUserAgent']('');

      expect(result).toEqual({});
    });

    it('should handle unknown user agent patterns', () => {
      const userAgent = 'SomeUnknownBrowser/1.0 CustomOS/1.0';
      
      const result = service['parseUserAgent'](userAgent);

      expect(result.os).toBeUndefined();
      expect(result.browser).toBeUndefined();
      expect(result.deviceType).toBe('desktop'); // Default for unknown
    });
  });

  describe('Edge Cases', () => {
    it('should handle user agent with mixed case', () => {
      const userAgent = 'mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/91.0.4472.124 safari/537.36';
      
      const result = service['parseUserAgent'](userAgent);

      expect(result.os).toBe('Windows');
      expect(result.browser).toBe('Chrome');
    });

    it('should handle user agent with unusual formatting', () => {
      const userAgent = 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)';
      
      const result = service['parseUserAgent'](userAgent);

      expect(result.os).toBe('Windows');
      // IE might not be detected by current logic, but should not crash
    });

    it('should handle very long user agent strings', () => {
      const longUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' + 
        'AppleWebKit/537.36 (KHTML, like Gecko) ' +
        'Chrome/91.0.4472.124 Safari/537.36 ' +
        'Additional/Info More/Data Extra/Content '.repeat(10);
      
      const result = service['parseUserAgent'](longUserAgent);

      expect(result.os).toBe('Windows');
      expect(result.browser).toBe('Chrome');
    });
  });
});