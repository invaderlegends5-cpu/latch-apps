// device-fingerprinting.bot-detection.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { DeviceFingerprintingService } from '../device-fingerprinting.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { SecurityMonitoringService } from '@/security/security-monitor.service';
import { ConfigService } from '@nestjs/config';

describe('DeviceFingerprintingService - Bot Detection', () => {
  let service: DeviceFingerprintingService;
  let prismaService: jest.Mocked<PrismaService>;
  let eventLogService: jest.Mocked<EventLogService>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        DeviceFingerprintingService,
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
        { provide: SecurityMonitoringService, useValue: {} },
        { provide: ConfigService, useValue: {} },
      ],
    }).compile();

    service = module.get<DeviceFingerprintingService>(DeviceFingerprintingService);
    prismaService = module.get(PrismaService);
    eventLogService = module.get(EventLogService);
  });

  describe('User Agent Analysis for Bot Detection', () => {
    it('should detect known bots by user agent', () => {
      const knownBots = [
        'Googlebot/2.1 (+http://www.google.com/bot.html)',
        'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)',
        'DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)',
        'facebookexternalhit/1.1',
        'Twitterbot/1.0',
      ];

      knownBots.forEach(userAgent => {
        const analysis = service['analyzeUserAgentForBot'](userAgent);
        expect(analysis.isBot).toBe(true);
        expect(analysis.confidence).toBe(0.9);
        expect(analysis.indicator).toContain('Known bot signature');
      });
    });

    it('should detect non-browser clients', () => {
      const nonBrowserClients = [
        'python-requests/2.28.1',
        'java/1.8.0_291',
        'curl/7.68.0',
        'Wget/1.20.3',
        'PostmanRuntime/7.28.4',
        'axios/0.21.1',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/91.0.4472.114 Safari/537.36',
      ];

      nonBrowserClients.forEach(userAgent => {
        const analysis = service['analyzeUserAgentForBot'](userAgent);
        expect(analysis.isBot).toBe(true);
        expect(analysis.confidence).toBe(0.7);
        expect(analysis.indicator).toContain('Non-browser client');
      });
    });

    it('should detect minimal user agents', () => {
      const minimalUserAgent = 'Mozilla/5.0';
      const analysis = service['analyzeUserAgentForBot'](minimalUserAgent);

      expect(analysis.isBot).toBe(true);
      expect(analysis.confidence).toBe(0.7);
      expect(analysis.indicator).toContain('Minimal user agent');
    });

    it('should return normal for legitimate browsers', () => {
      const normalBrowsers = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
      ];

      normalBrowsers.forEach(userAgent => {
        const analysis = service['analyzeUserAgentForBot'](userAgent);
        expect(analysis.isBot).toBe(false);
        expect(analysis.confidence).toBe(0);
        expect(analysis.indicator).toBe('Normal user agent');
      });
    });

    it('should handle null user agent', () => {
      const analysis = service['analyzeUserAgentForBot'](null);

      expect(analysis.isBot).toBe(false);
      expect(analysis.confidence).toBe(0);
      expect(analysis.indicator).toBe('No user agent');
    });
  });

  describe('Timing Analysis for Bot Detection', () => {
    it('should detect very fast response times', () => {
      const analysis = service['analyzeTimingForBot'](5); // 5ms

      expect(analysis.isBot).toBe(true);
      expect(analysis.confidence).toBe(0.6);
      expect(analysis.indicator).toContain('Very fast response: 5ms');
    });

    it('should detect very slow response times', () => {
      const analysis = service['analyzeTimingForBot'](6000); // 6 seconds

      expect(analysis.isBot).toBe(true);
      expect(analysis.confidence).toBe(0.4);
      expect(analysis.indicator).toContain('Very slow response: 6000ms');
    });

    it('should return normal for reasonable response times', () => {
      const analysis = service['analyzeTimingForBot'](150); // 150ms

      expect(analysis.isBot).toBe(false);
      expect(analysis.confidence).toBe(0);
      expect(analysis.indicator).toBe('Normal response time');
    });

    it('should handle zero response time', () => {
      const analysis = service['analyzeTimingForBot'](0);

      expect(analysis.isBot).toBe(false);
      expect(analysis.confidence).toBe(0);
      expect(analysis.indicator).toBe('No timing data');
    });
  });

  describe('Pattern Analysis for Bot Detection', () => {
    it('should detect suspicious URL patterns', () => {
      const suspiciousUrls = [
        '/admin',
        '/wp-admin',
        '/phpmyadmin',
        '/backup',
        '/config',
        '/private',
        '/api/graphql',
        '/graphql',
      ];

      suspiciousUrls.forEach(url => {
        const analysis = service['analyzePatternForBot']('GET', url);
        expect(analysis.isBot).toBe(true);
        expect(analysis.confidence).toBe(0.4);
        expect(analysis.indicator).toContain('Suspicious URL');
      });
    });

    it('should detect suspicious HTTP methods', () => {
      const suspiciousMethods = ['TRACE', 'CONNECT', 'OPTIONS'];

      suspiciousMethods.forEach(method => {
        const analysis = service['analyzePatternForBot'](method, '/api/test');
        expect(analysis.isBot).toBe(true);
        expect(analysis.confidence).toBe(0.5);
        expect(analysis.indicator).toContain(`Suspicious method: ${method}`);
      });
    });

    it('should return normal for safe patterns', () => {
      const analysis = service['analyzePatternForBot']('GET', '/api/users/profile');

      expect(analysis.isBot).toBe(false);
      expect(analysis.confidence).toBe(0);
      expect(analysis.indicator).toBe('Normal pattern');
    });
  });

  describe('Session Analysis for Bot Detection', () => {
    it('should analyze session and return normal behavior', async () => {
      prismaService.session.findUnique.mockResolvedValue({
        id: 'session-123',
        userId: 'user-123',
        tenantId: 'tenant-123',
        refreshHash: 'hash',
        userAgent: 'test-agent',
        ipAddress: '192.168.1.1',
        createdAt: new Date(),
        lastActiveAt: new Date(),
        expiresAt: new Date(Date.now() + 3600000),
        revoked: false,
        csrfToken: 'csrf-token',
      });

      const analysis = await service['analyzeSessionForBot']('session-123');

      expect(analysis.isBot).toBe(false);
      expect(analysis.confidence).toBe(0);
      expect(analysis.indicator).toBe('Normal session');
    });

    it('should handle session not found', async () => {
      prismaService.session.findUnique.mockResolvedValue(null);

      const analysis = await service['analyzeSessionForBot']('non-existent-session');

      expect(analysis.isBot).toBe(false);
      expect(analysis.confidence).toBe(0);
      expect(analysis.indicator).toBe('Session not found');
    });

    it('should handle null session ID', async () => {
      const analysis = await service['analyzeSessionForBot'](null);

      expect(analysis.isBot).toBe(false);
      expect(analysis.confidence).toBe(0);
      expect(analysis.indicator).toBe('No session');
    });

    it('should handle database errors', async () => {
      prismaService.session.findUnique.mockRejectedValue(new Error('DB error'));

      const analysis = await service['analyzeSessionForBot']('session-123');

      expect(analysis.isBot).toBe(false);
      expect(analysis.confidence).toBe(0);
      expect(analysis.indicator).toBe('Session analysis error');
    });
  });

  describe('Risk Score Calculation', () => {
    it('should calculate device risk score correctly', () => {
      const userAgentConfidence = 0.9; // High bot confidence
      const timingConfidence = 0.6;    // Medium bot confidence
      const patternConfidence = 0.3;   // Low bot confidence
      const sessionConfidence = 0.1;   // Very low bot confidence

      const riskScore = service['calculateDeviceRiskScore'](
        userAgentConfidence,
        timingConfidence,
        patternConfidence,
        sessionConfidence
      );

      // Weighted calculation: (0.9*0.3 + 0.6*0.25 + 0.3*0.25 + 0.1*0.2) / (0.3+0.25+0.25+0.2)
      // = (0.27 + 0.15 + 0.075 + 0.02) / 1 = 0.515
      expect(riskScore).toBeCloseTo(0.515);
    });

    it('should handle zero confidence values', () => {
      const riskScore = service['calculateDeviceRiskScore'](0, 0, 0, 0);
      expect(riskScore).toBe(0);
    });
  });

  describe('Risk Score to Event Severity Mapping', () => {
    it('should map risk scores to event severity correctly', () => {
      expect(service['mapRiskScoreToEventSeverity'](0.1)).toBe('INFO');
      expect(service['mapRiskScoreToEventSeverity'](0.5)).toBe('SECURITY');
      expect(service['mapRiskScoreToEventSeverity'](0.7)).toBe('SECURITY');
      expect(service['mapRiskScoreToEventSeverity'](0.95)).toBe('CRITICAL');
    });
  });
});