// behavioral-analysis.cleanup.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { BehavioralAnalysisService } from '../behavioral-analysis.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { SecurityMonitoringService } from '@/security/security-monitor.service';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';
import { DeviceFingerprintingService } from '@/device-fingerprinting/device-fingerprinting.service';
import { ConfigService } from '@nestjs/config';
import { BehavioralSession } from '../types/behavior.types';

describe('BehavioralAnalysisService - Cleanup', () => {
  let service: BehavioralAnalysisService;
  let prismaService: jest.Mocked<PrismaService>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        BehavioralAnalysisService,
        {
          provide: PrismaService,
          useValue: {
            event: {
              findMany: jest.fn(),
            },
          },
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
          useValue: {},
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
    prismaService = module.get(PrismaService);
  });

  describe('Session Cleanup', () => {
    it('should cleanup old sessions and associated data', () => {
      const now = Date.now();
      const oldTime = now - 2 * 60 * 60 * 1000; // 2 hours ago (older than 1h retention)
      const recentTime = now - 30 * 60 * 1000; // 30 minutes ago

      // Set up old and recent sessions
      service['behavioralSessions'].set('old-session', {
        sessionId: 'old-session',
        userId: 'user-1',
        ipAddress: '192.168.1.1',
        userAgent: 'old-agent',
        firstRequest: new Date(oldTime),
        lastRequest: new Date(oldTime),
        totalRequests: 5,
        requestIntervalStats: { mean: 0, stdDev: 0, min: 0, max: 0 },
        navigationSequence: [],
        suspiciousIndicators: [],
        riskScore: 0,
        riskLevel: 'LOW',
      });

      service['behavioralSessions'].set('recent-session', {
        sessionId: 'recent-session',
        userId: 'user-2',
        ipAddress: '192.168.1.2',
        userAgent: 'recent-agent',
        firstRequest: new Date(recentTime),
        lastRequest: new Date(recentTime),
        totalRequests: 3,
        requestIntervalStats: { mean: 0, stdDev: 0, min: 0, max: 0 },
        navigationSequence: [],
        suspiciousIndicators: [],
        riskScore: 0,
        riskLevel: 'LOW',
      });

      // Set up tracking maps
      service['ipSessionMap'].set('192.168.1.1', new Set(['old-session']));
      service['ipSessionMap'].set('192.168.1.2', new Set(['recent-session']));
      service['userSessionMap'].set('user-1', new Set(['old-session']));
      service['userSessionMap'].set('user-2', new Set(['recent-session']));

      // Set up request history
      service['requestHistory'].set('old-session', [
        { timestamp: new Date(oldTime), method: 'GET', url: '/old', userAgent: 'old', ipAddress: '192.168.1.1', sessionId: 'old-session', userId: 'user-1', responseTime: 150, userAgentChange: false, ipChange: false },
      ]);
      service['requestHistory'].set('recent-session', [
        { timestamp: new Date(recentTime), method: 'GET', url: '/recent', userAgent: 'recent', ipAddress: '192.168.1.2', sessionId: 'recent-session', userId: 'user-2', responseTime: 150, userAgentChange: false, ipChange: false },
      ]);

      service['cleanupOldSessions']();

      // Old session should be removed
      expect(service['behavioralSessions'].has('old-session')).toBe(false);
      expect(service['behavioralSessions'].has('recent-session')).toBe(true);

      // Tracking maps should be cleaned up
      expect(service['ipSessionMap'].has('192.168.1.1')).toBe(false);
      expect(service['ipSessionMap'].get('192.168.1.2')?.has('recent-session')).toBe(true);

      expect(service['userSessionMap'].has('user-1')).toBe(false);
      expect(service['userSessionMap'].get('user-2')?.has('recent-session')).toBe(true);

      // Request history should be cleaned up
      expect(service['requestHistory'].has('old-session')).toBe(false);
      expect(service['requestHistory'].has('recent-session')).toBe(true);
    });

    it('should cleanup empty IP and user session sets', () => {
        // Setup the cutoff date used internally by the service (~1 hour ago typically)
        const sessionRetentionMs =service['config'].sessionRetention; 
        const cutoffTime = new Date(Date.now() - sessionRetentionMs - 10000); // Definitely make it old
  
        // Setup session data where the lastRequest is OLD
        const mockOldSession: BehavioralSession = {
          sessionId: 'old-session-id',
          ipAddress: '192.168.1.100',
          userId: 'user-100',
          lastRequest: cutoffTime,
          firstRequest: new Date(), 
          riskScore: 0, 
          totalRequests: 1, 
          navigationSequence: [], 
          suspiciousIndicators: [], 
          riskLevel: 'LOW',
          
          // --- FIX: Add missing required fields ---
          userAgent: '', 
          requestIntervalStats: {
              mean: 0,
              stdDev: 0,
              min: 0,
              max: 0
          },
        };
  
        // Manually populate the service maps for the test
        service['behavioralSessions'].set(mockOldSession.sessionId, mockOldSession);
        service['ipSessionMap'].set(mockOldSession.ipAddress!, new Set([mockOldSession.sessionId]));
        service['userSessionMap'].set(mockOldSession.userId!, new Set([mockOldSession.sessionId]));
  
        // Run the cleanup
        service['cleanupOldSessions']();
  
        // Assertions should now pass because the service logic is robust
        expect(service['ipSessionMap'].has('192.168.1.100')).toBe(false);
        expect(service['userSessionMap'].has('user-100')).toBe(false);
        expect(service['behavioralSessions'].has('old-session-id')).toBe(false);
      });
  });

  describe('Request History Cleanup', () => {
    it('should cleanup old request history entries', () => {
      const sessionKey = 'test-session';
      const now = Date.now();
      const oldTime = now - 2 * 60 * 60 * 1000; // 2 hours ago
      const recentTime = now - 30 * 60 * 1000; // 30 minutes ago

      const history = [
        { timestamp: new Date(oldTime), method: 'GET', url: '/old', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test-session', userId: 'user-1', responseTime: 150, userAgentChange: false, ipChange: false },
        { timestamp: new Date(recentTime), method: 'GET', url: '/recent', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test-session', userId: 'user-1', responseTime: 150, userAgentChange: false, ipChange: false },
        { timestamp: new Date(now), method: 'GET', url: '/current', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'test-session', userId: 'user-1', responseTime: 150, userAgentChange: false, ipChange: false },
      ];

      service['requestHistory'].set(sessionKey, history);
      service['cleanupOldSessions']();

      const updatedHistory = service['requestHistory'].get(sessionKey);
      expect(updatedHistory).toHaveLength(2); // Only recent and current should remain
      expect(updatedHistory?.[0].url).toBe('/recent');
      expect(updatedHistory?.[1].url).toBe('/current');
    });

    it('should remove session key when all history is old', () => {
      const sessionKey = 'old-session-only';
      const oldTime = Date.now() - 2 * 60 * 60 * 1000;

      service['requestHistory'].set(sessionKey, [
        { timestamp: new Date(oldTime), method: 'GET', url: '/old', userAgent: 'test', ipAddress: '192.168.1.1', sessionId: 'old-session-only', userId: 'user-1', responseTime: 150, userAgentChange: false, ipChange: false },
      ]);

      service['cleanupOldSessions']();

      expect(service['requestHistory'].has(sessionKey)).toBe(false);
    });
  });

  describe('Profile Management', () => {
    it('should load behavioral profiles from database', async () => {
      const mockEvents = [
        {
          id: 'event-1',
          userId: 'user-1',
          type: 'LOGIN',
          severity: 'INFO',
          metadata: {},
          createdAt: new Date(),
          updatedAt: new Date(),
          tenantId: null,
          sessionId: null,
          familyId: null,
          reason: null,
          integrityHash: 'hash1',
          prevHash: null,
          ipAddress: '192.168.1.1',
          userAgent: 'test-agent',
        },
        {
          id: 'event-2', 
          userId: 'user-2',
          type: 'LOGOUT',
          severity: 'INFO',
          metadata: {},
          createdAt: new Date(),
          updatedAt: new Date(),
          tenantId: null,
          sessionId: null,
          familyId: null,
          reason: null,
          integrityHash: 'hash2',
          prevHash: null,
          ipAddress: '192.168.1.2',
          userAgent: 'test-agent',
        },
      ];

      prismaService.event.findMany.mockResolvedValue(mockEvents);

      await service['loadBehavioralProfiles']();

      expect(prismaService.event.findMany).toHaveBeenCalledWith({
        where: {
          createdAt: { gte: expect.any(Date) },
        },
        orderBy: { createdAt: 'desc' },
        take: 10000,
      });

      // Should create profiles for users with events
      expect(service['behavioralProfiles'].has('user-1')).toBe(true);
      expect(service['behavioralProfiles'].has('user-2')).toBe(true);
    });

    it('should create default profile for user', () => {
      const userId = 'new-user';
      const profile = service['createDefaultProfile'](userId);

      expect(profile.userId).toBe(userId);
      expect(profile.requestPattern.avgInterval).toBe(2000);
      expect(profile.requestPattern.peakActivityHours).toEqual([9, 10, 11, 14, 15, 16]);
      expect(profile.lastUpdated).toBeInstanceOf(Date);
    });

    it('should handle profile loading errors gracefully', async () => {
      prismaService.event.findMany.mockRejectedValue(new Error('Database error'));

      await expect(service['loadBehavioralProfiles']()).resolves.not.toThrow();
    });
  });
});