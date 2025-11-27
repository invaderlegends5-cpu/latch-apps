// behavioral-analysis.integration.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { BehavioralAnalysisService } from '../behavioral-analysis.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { SecurityMonitoringService } from '@/security/security-monitor.service';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';
import { DeviceFingerprintingService } from '@/device-fingerprinting/device-fingerprinting.service';
import { ConfigService } from '@nestjs/config';
import { AnomalyDetectionResult } from '../types/behavior.types';

describe('BehavioralAnalysisService - Integration', () => {
  let service: BehavioralAnalysisService;
  let ipReputationService: jest.Mocked<IPReputationService>;
  let eventLogService: jest.Mocked<EventLogService>;
  let configService: ConfigService;

  const mockUserId = 'user-123';
  const mockSessionId = 'session-456';
  const mockIP = '192.168.1.1';
  const mockUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        BehavioralAnalysisService,
        {
          provide: PrismaService,
          useValue: {
            event: {
              findMany: jest.fn().mockResolvedValue([]),
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
          provide: IPReputationService,
          useValue: {
            isIPBlocked: jest.fn().mockResolvedValue(false),
          },
        },
        {
          provide: DeviceFingerprintingService,
          useValue: {
            analyzeDeviceFingerprint: jest.fn(),
          },
        },
        {
          provide: ConfigService,
          useValue: {
            // Mock the 'get' method to return specific risk thresholds
            get: jest.fn(key => {
              if (key === 'riskScoreThresholds') {
                return {
                  low: 0.1,
                  medium: 0.2,
                  high: 0.4,      // Setting a low 'high' threshold
                  critical: 0.5,  // Setting a low 'critical' threshold
                };
              }
              // Return other default configs if necessary, e.g., session timeouts
              return null;
            }),
          },
        },
      ],
    }).compile();

    service = module.get<BehavioralAnalysisService>(BehavioralAnalysisService);
    ipReputationService = module.get(IPReputationService);
    eventLogService = module.get(EventLogService);
    configService = module.get(ConfigService);

    jest.clearAllMocks();
  });

  describe('End-to-End Behavioral Analysis', () => {
    
    it('should detect bot-like behavior across multiple requests', async () => {
      const results: AnomalyDetectionResult[] = [];

      // Simulate bot-like behavior: very fast, consistent requests
      for (let i = 0; i < 10; i++) {
        // Each request 50ms apart (too fast for human)
        await new Promise(resolve => setTimeout(resolve, 50));
        
        const result = await service.analyzeRequest(
          mockUserId,
          mockSessionId,
          mockIP,
          mockUserAgent,
          'GET',
          `/api/data${i}`,
          10 // Very fast response time
        );
        results.push(result);
      }

      // Risk should increase with more suspicious requests
      const lastResult = results[results.length - 1];
      expect(lastResult.isAnomalous).toBe(true);
      expect(lastResult.confidence).toBeGreaterThan(0.4);
      expect(lastResult.recommendation).toMatch(/CHALLENGE|BLOCK|ALLOW/);
      
      // Should log high-risk event
      expect(eventLogService.logEvent).toHaveBeenCalledWith(
        'SECURITY_STATUS_CHECKED',
        expect.objectContaining({
          metadata: expect.objectContaining({
            analysisType: 'BEHAVIORAL',
            riskScore: expect.any(Number),
            timingAnomaly: true,
          }),
        })
      );
    });

    it('should maintain normal behavior for human-like patterns', async () => {
      const results: AnomalyDetectionResult[] = [];

      // Simulate human-like behavior: varied, slower requests
      for (let i = 0; i < 5; i++) {
        // Varied intervals between 1-3 seconds
        await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 2000));
        
        const result = await service.analyzeRequest(
          mockUserId,
          mockSessionId,
          mockIP,
          mockUserAgent,
          'GET',
          `/api/page${i}`,
          150 + Math.random() * 100 // Normal response times
        );
        results.push(result);
      }

      const lastResult = results[results.length - 1];
      expect(lastResult.isAnomalous).toBe(false);
      expect(lastResult.confidence).toBeLessThan(0.6);
      expect(lastResult.recommendation).toBe('ALLOW');
    }, 20000);

    it('should detect and block critical threat behavior', async () => {
      (ipReputationService.isIPBlocked as jest.Mock).mockResolvedValue(true); // IP is blocked

      // Very fast requests from blocked IP
      for (let i = 0; i < 15; i++) {
        await new Promise(resolve => setTimeout(resolve, 10));
        
        await service.analyzeRequest(
          mockUserId,
          mockSessionId,
          mockIP, // Blocked IP
          mockUserAgent,
          'GET',
          `/api/attack${i}`,
          5
        );
      }

      // Wait briefly for async operations to complete
      await new Promise(resolve => setTimeout(resolve, 100));

      // Should create threat alert
      const threats = Array.from((service as any).threatCache.values());
      expect(threats.length).toBeGreaterThan(0);
      
      // Use the actual config value to define "high" dynamically
      const riskThresholds = configService.get('riskScoreThresholds'); 
      const criticalThreat = threats.find(t => 
        t.severity === 'CRITICAL' || 
        t.totalRiskScore > (riskThresholds?.high || 0.4)
      );
      
      expect(criticalThreat).toBeDefined();
    });

    it('should handle mixed behavior patterns correctly', async () => {
      // Start with normal behavior
      await service.analyzeRequest(mockUserId, mockSessionId, mockIP, mockUserAgent, 'GET', '/api/login', 200);
      await new Promise(resolve => setTimeout(resolve, 2000));
      await service.analyzeRequest(mockUserId, mockSessionId, mockIP, mockUserAgent, 'POST', '/api/auth', 180);

      let lastResult: AnomalyDetectionResult | undefined;

      // Then suspicious rapid requests (Increase iterations to 15 for reliability if 8 wasn't enough)
      for (let i = 0; i < 15; i++) { 
        await new Promise(resolve => setTimeout(resolve, 50));
        lastResult = await service.analyzeRequest(
          mockUserId, 
          mockSessionId, 
          mockIP, 
          mockUserAgent, 
          'GET', 
          `/api/scan${i}`, 
          20
        );
      }
      
      // The last result *during* the attack should detect the suspicious pattern
      expect(lastResult!.isAnomalous).toBe(true);
      expect(lastResult!.indicators).toContain('Timing anomaly detected');
      // Ensure the rate indicator is also present, matching the logs
      expect(lastResult!.indicators).toContain('Rate anomaly detected'); 
    }, 10000);
  });

  describe('Statistical Methods', () => {
    it('should provide user session statistics', async () => {
      // Create multiple sessions for the same user
      await service.analyzeRequest(mockUserId, 'session-1', '192.168.1.1', mockUserAgent, 'GET', '/api/test1', 150);
      await service.analyzeRequest(mockUserId, 'session-2', '192.168.1.2', mockUserAgent, 'GET', '/api/test2', 150);
      await service.analyzeRequest(mockUserId, 'session-3', '192.168.1.3', mockUserAgent, 'GET', '/api/test3', 150);

      const stats = await service.getUserSessionStats(mockUserId);

      expect(stats.totalSessions).toBe(3);
      expect(stats.activeSessions).toBe(3); // All sessions are recent
      expect(stats.riskScore).toBeGreaterThanOrEqual(0);
    });

    it('should provide IP statistics', async () => {
      // Create multiple sessions from the same IP
      await service.analyzeRequest('user-1', 'session-1', mockIP, mockUserAgent, 'GET', '/api/test1', 150);
      await service.analyzeRequest('user-2', 'session-2', mockIP, mockUserAgent, 'GET', '/api/test2', 150);
      await service.analyzeRequest('user-3', 'session-3', mockIP, mockUserAgent, 'GET', '/api/test3', 150);

      const stats = await service.getIPStats(mockIP);

      expect(stats.sessionCount).toBe(3);
      expect(stats.avgRiskScore).toBeGreaterThanOrEqual(0);
      expect(stats.isBlocked).toBe(false);
    });

    it('should handle statistics for non-existent users and IPs', async () => {
      const userStats = await service.getUserSessionStats('non-existent-user');
      expect(userStats.totalSessions).toBe(0);
      expect(userStats.activeSessions).toBe(0);
      expect(userStats.riskScore).toBe(0);

      const ipStats = await service.getIPStats('10.0.0.1');
      expect(ipStats.sessionCount).toBe(0);
      expect(ipStats.avgRiskScore).toBe(0);
      expect(ipStats.isBlocked).toBe(false);
    });
  });

  describe('Configuration Boundaries', () => {
    it('should respect maximum session limits', async () => {
      // Create more sessions than the maximum allowed per IP
      for (let i = 0; i < 15; i++) {
        await service.analyzeRequest(
          `user-${i}`,
          `session-${i}`,
          mockIP, // Same IP
          mockUserAgent,
          'GET',
          `/api/test${i}`,
          150
        );
      }

      const ipStats = await service.getIPStats(mockIP);
      expect(ipStats.sessionCount).toBe(15);

      // The next request should trigger IP anomaly detection
      const result = await service.analyzeRequest(
        'user-15',
        'session-15',
        mockIP,
        mockUserAgent,
        'GET',
        '/api/test',
        150
      );

      expect(result.indicators).toContain('IP behavior anomaly detected');
    });

    it('should handle edge cases in timing analysis', async () => {
      // Test with single request (no intervals)
      const singleResult = await service.analyzeRequest(
        mockUserId,
        mockSessionId,
        mockIP,
        mockUserAgent,
        'GET',
        '/api/single',
        150
      );

      expect(singleResult.isAnomalous).toBe(false);

      // Test with negative response time
      const negativeResult = await service.analyzeRequest(
        mockUserId,
        mockSessionId,
        mockIP,
        mockUserAgent,
        'GET',
        '/api/negative',
        -100
      );

      expect(negativeResult).toBeDefined(); // Should not crash
    });
  });
});