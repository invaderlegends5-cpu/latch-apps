// behavioral-analysis.session.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { BehavioralAnalysisService } from '../behavioral-analysis.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { SecurityMonitoringService } from '@/security/security-monitor.service';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';
import { DeviceFingerprintingService } from '@/device-fingerprinting/device-fingerprinting.service';
import { ConfigService } from '@nestjs/config';
import { BehavioralSession, SuspiciousIndicator } from '../types/behavior.types';

describe('BehavioralAnalysisService - Session Behavior', () => {
  let service: BehavioralAnalysisService;
  let ipReputationService: jest.Mocked<IPReputationService>;

  const mockUserId = 'user-123';
  const mockIP = '192.168.1.1';

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        BehavioralAnalysisService,
        {
          provide: PrismaService,
          useValue: {},
        },
        {
          provide: EventLogService,
          useValue: {},
        },
        {
          provide: SecurityMonitoringService,
          useValue: {},
        },
        {
          provide: IPReputationService,
          useValue: {
            isIPBlocked: jest.fn(),
          },
        },
        {
          provide: DeviceFingerprintingService,
          useValue: {},
        },
        {
          provide: ConfigService,
            useValue: {
             get: jest.fn(key => {
              if (key === 'riskScoreThresholds') {
                return {
                  low: 0.2,
                  medium: 0.4,
                  high: 0.7,
                  critical: 0.9,
                };
              }
              // Return other config values as needed
              return null;
            }),
          },
        },
      ],
    }).compile();

    service = module.get<BehavioralAnalysisService>(BehavioralAnalysisService);
    ipReputationService = module.get(IPReputationService);
  });

  describe('IP Behavior Analysis', () => {
    it('should detect blocked IP as anomalous', async () => {
      ipReputationService.isIPBlocked.mockResolvedValue(true);

      const session: BehavioralSession = {
        sessionId: 'test-session',
        userId: mockUserId,
        ipAddress: mockIP,
        userAgent: 'test-agent',
        firstRequest: new Date(),
        lastRequest: new Date(),
        totalRequests: 5,
        requestIntervalStats: { mean: 0, stdDev: 0, min: 0, max: 0 },
        navigationSequence: [],
        suspiciousIndicators: [],
        riskScore: 0,
        riskLevel: 'LOW',
      };

      const analysis = await service['analyzeIPBehavior'](session, 'test-session');

      expect(analysis.isAnomalous).toBe(true);
      expect(analysis.indicators).toContain('IP is blocked');
    });

    it('should detect too many sessions from single IP', async () => {
      ipReputationService.isIPBlocked.mockResolvedValue(false);

      // Set up multiple sessions for the same IP
      for (let i = 0; i < 12; i++) {
        service['ipSessionMap'].set(mockIP, new Set([...Array(i + 1)].map((_, idx) => `session-${idx}`)));
      }

      const session: BehavioralSession = {
        sessionId: 'new-session',
        userId: mockUserId,
        ipAddress: mockIP,
        userAgent: 'test-agent',
        firstRequest: new Date(),
        lastRequest: new Date(),
        totalRequests: 5,
        requestIntervalStats: { mean: 0, stdDev: 0, min: 0, max: 0 },
        navigationSequence: [],
        suspiciousIndicators: [],
        riskScore: 0,
        riskLevel: 'LOW',
      };

      const analysis = await service['analyzeIPBehavior'](session, 'new-session');

      expect(analysis.isAnomalous).toBe(true);
      expect(analysis.indicators).toContain('Too many sessions from single IP (12)');
    });

    it('should return non-anomalous for normal IP behavior', async () => {
      ipReputationService.isIPBlocked.mockResolvedValue(false);

      // Set up normal number of sessions
      service['ipSessionMap'].set(mockIP, new Set(['session-1', 'session-2']));

      const session: BehavioralSession = {
        sessionId: 'session-3',
        userId: mockUserId,
        ipAddress: mockIP,
        userAgent: 'test-agent',
        firstRequest: new Date(),
        lastRequest: new Date(),
        totalRequests: 5,
        requestIntervalStats: { mean: 0, stdDev: 0, min: 0, max: 0 },
        navigationSequence: [],
        suspiciousIndicators: [],
        riskScore: 0,
        riskLevel: 'LOW',
      };

      const analysis = await service['analyzeIPBehavior'](session, 'session-3');

      expect(analysis.isAnomalous).toBe(false);
      expect(analysis.indicators).toHaveLength(0);
    });
  });

  describe('Session Behavior Analysis', () => {
    it('should detect too many concurrent sessions for user', () => {
      // Set up multiple sessions for the same user
      for (let i = 0; i < 6; i++) {
        service['userSessionMap'].set(mockUserId, new Set([...Array(i + 1)].map((_, idx) => `session-${idx}`)));
      }

      const session: BehavioralSession = {
        sessionId: 'new-session',
        userId: mockUserId,
        ipAddress: mockIP,
        userAgent: 'test-agent',
        firstRequest: new Date(),
        lastRequest: new Date(),
        totalRequests: 5,
        requestIntervalStats: { mean: 0, stdDev: 0, min: 0, max: 0 },
        navigationSequence: [],
        suspiciousIndicators: [],
        riskScore: 0,
        riskLevel: 'LOW',
      };

      const analysis = service['analyzeSessionBehavior'](session, mockIP, mockUserId);

      expect(analysis.isAnomalous).toBe(true);
      expect(analysis.indicators).toHaveLength(1);
      expect(analysis.indicators[0].type).toBe('RATE_ANOMALY');
      expect(analysis.indicators[0].severity).toBe('HIGH');
      expect(analysis.indicators[0].evidence).toContain('Too many concurrent sessions for user (6)');
    });

    it('should return non-anomalous for normal session behavior', () => {
      // Set up normal number of sessions
      service['userSessionMap'].set(mockUserId, new Set(['session-1', 'session-2']));

      const session: BehavioralSession = {
        sessionId: 'session-3',
        userId: mockUserId,
        ipAddress: mockIP,
        userAgent: 'test-agent',
        firstRequest: new Date(),
        lastRequest: new Date(),
        totalRequests: 5,
        requestIntervalStats: { mean: 0, stdDev: 0, min: 0, max: 0 },
        navigationSequence: [],
        suspiciousIndicators: [],
        riskScore: 0,
        riskLevel: 'LOW',
      };

      const analysis = service['analyzeSessionBehavior'](session, mockIP, mockUserId);

      expect(analysis.isAnomalous).toBe(false);
      expect(analysis.indicators).toHaveLength(0);
    });

    it('should handle sessions without user ID', () => {
      const session: BehavioralSession = {
        sessionId: 'anonymous-session',
        userId: 'unknown',
        ipAddress: mockIP,
        userAgent: 'test-agent',
        firstRequest: new Date(),
        lastRequest: new Date(),
        totalRequests: 5,
        requestIntervalStats: { mean: 0, stdDev: 0, min: 0, max: 0 },
        navigationSequence: [],
        suspiciousIndicators: [],
        riskScore: 0,
        riskLevel: 'LOW',
      };

      const analysis = service['analyzeSessionBehavior'](session, mockIP, null);

      expect(analysis.isAnomalous).toBe(false);
      expect(analysis.indicators).toHaveLength(0);
    });
  });

  describe('Session Management', () => {
    it('should create new behavioral session correctly', () => {
      const requestPattern = {
        timestamp: new Date(),
        method: 'GET',
        url: '/api/test',
        userAgent: 'test-agent',
        ipAddress: mockIP,
        sessionId: 'test-session',
        userId: mockUserId,
        responseTime: 150,
        userAgentChange: false,
        ipChange: false,
      };

      const session = service['createBehavioralSession'](requestPattern);

      expect(session.sessionId).toBe('test-session');
      expect(session.userId).toBe(mockUserId);
      expect(session.ipAddress).toBe(mockIP);
      expect(session.userAgent).toBe('test-agent');
      expect(session.totalRequests).toBe(1);
      expect(session.navigationSequence).toEqual(['/api/test']);
      expect(session.riskLevel).toBe('LOW');
      expect(session.riskScore).toBe(0);
    });

    it('should generate session key when no session ID provided', () => {
      const requestPattern = {
        timestamp: new Date(),
        method: 'GET',
        url: '/api/test',
        userAgent: 'test-agent',
        ipAddress: mockIP,
        sessionId: null,
        userId: mockUserId,
        responseTime: 150,
        userAgentChange: false,
        ipChange: false,
      };

      const session = service['createBehavioralSession'](requestPattern);

      expect(session.sessionId).toMatch(/session-\d+/);
    });

    it('should update existing session correctly', () => {
      const existingSession: BehavioralSession = {
        sessionId: 'test-session',
        userId: mockUserId,
        ipAddress: mockIP,
        userAgent: 'test-agent',
        firstRequest: new Date(Date.now() - 10000),
        lastRequest: new Date(Date.now() - 5000),
        totalRequests: 5,
        requestIntervalStats: { mean: 1000, stdDev: 200, min: 800, max: 1200 },
        navigationSequence: ['/api/a', '/api/b'],
        suspiciousIndicators: [],
        riskScore: 0.2,
        riskLevel: 'LOW',
      };

      const newRequest = {
        timestamp: new Date(),
        method: 'POST',
        url: '/api/c',
        userAgent: 'test-agent',
        ipAddress: mockIP,
        sessionId: 'test-session',
        userId: mockUserId,
        responseTime: 200,
        userAgentChange: false,
        ipChange: false,
      };

      const updatedSession = service['updateBehavioralSession'](existingSession, newRequest);

      expect(updatedSession.totalRequests).toBe(6);
      expect(updatedSession.lastRequest).toBe(newRequest.timestamp);
      expect(updatedSession.navigationSequence).toContain('/api/c');
      expect(updatedSession.navigationSequence).toHaveLength(3);
    });

    it('should limit navigation sequence size', () => {
        const MAX_NAV_LENGTH = 50; 
      const existingSession: BehavioralSession = {
        sessionId: 'test-session',
        userId: mockUserId,
        ipAddress: mockIP,
        userAgent: 'test-agent',
        firstRequest: new Date(),
        lastRequest: new Date(),
        totalRequests: 150,
        requestIntervalStats: { mean: 1000, stdDev: 200, min: 800, max: 1200 },
        navigationSequence: Array.from({ length: MAX_NAV_LENGTH }, (_, i) => `/api/page${i + 1}`),
        suspiciousIndicators: [],
        riskScore: 0.2,
        riskLevel: 'LOW',
      };

      const newRequest = {
        timestamp: new Date(),
        method: 'GET',
        url: '/api/new',
        userAgent: 'test-agent',
        ipAddress: mockIP,
        sessionId: 'test-session',
        userId: mockUserId,
        responseTime: 150,
        userAgentChange: false,
        ipChange: false,
      };

      const updatedSession = service['updateBehavioralSession'](existingSession, newRequest);

      expect(updatedSession.navigationSequence).toHaveLength(MAX_NAV_LENGTH);  // Should be limited to 50 + new
      // The newest item is at the end
      expect(updatedSession.navigationSequence[MAX_NAV_LENGTH - 1]).toBe('/api/new');

      // The oldest item (page 1) should be gone
      expect(updatedSession.navigationSequence).not.toContain('/api/page1');
      
      // The second oldest item (page 2) is now the oldest
      expect(updatedSession.navigationSequence[0]).toBe('/api/page2');
    });
    
  });

  describe('Request History Tracking', () => {
    it('should track request history for session', () => {
      const sessionKey = 'test-session';
      const requestPattern = {
        timestamp: new Date(),
        method: 'GET',
        url: '/api/test',
        userAgent: 'test-agent',
        ipAddress: mockIP,
        sessionId: 'test-session',
        userId: mockUserId,
        responseTime: 150,
        userAgentChange: false,
        ipChange: false,
      };

      service['trackRequestHistory'](sessionKey, requestPattern);

      const history = service['requestHistory'].get(sessionKey);
      expect(history).toHaveLength(1);
      expect(history?.[0]).toEqual(requestPattern);
    });

    it('should limit request history size', () => {
      const sessionKey = 'test-session';
      
      // Add more requests than the max limit
      for (let i = 0; i < 1500; i++) {
        const requestPattern = {
          timestamp: new Date(Date.now() + i * 1000),
          method: 'GET',
          url: `/api/test${i}`,
          userAgent: 'test-agent',
          ipAddress: mockIP,
          sessionId: 'test-session',
          userId: mockUserId,
          responseTime: 150,
          userAgentChange: false,
          ipChange: false,
        };
        service['trackRequestHistory'](sessionKey, requestPattern);
      }

      const history = service['requestHistory'].get(sessionKey);
      expect(history).toHaveLength(1000); // Should be limited to maxRequestHistory
      expect(history?.[0]?.url).toBe('/api/test500'); // Should keep the most recent
      expect(history?.[999]?.url).toBe('/api/test1499'); // Most recent at the end
    });
  });
});