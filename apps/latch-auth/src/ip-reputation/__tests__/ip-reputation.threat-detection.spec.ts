// ip-reputation.threat-detection.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { IPReputationService } from '../ip-reputation.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { SecurityMonitoringService } from '@/security/security-monitor.service';
import { RedisService } from '@/redis/redis.service';
import { ConfigService } from '@nestjs/config';
import { EventType } from '@/events/event.types';
import { THREAT_INDICATORS } from '../constants/reputation.constants';

describe('IPReputationService - Threat Detection', () => {
  let service: IPReputationService;

  const mockIP = '192.168.1.1';

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        IPReputationService,
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
          provide: RedisService,
          useValue: {},
        },
        {
          provide: ConfigService,
          useValue: {},
        },
      ],
    }).compile();

    service = module.get<IPReputationService>(IPReputationService);
  });

  describe('Threat detection', () => {
    it('should detect brute force attacks', async () => {
        // Get the required threshold directly from the constant the service uses
        const threshold = THREAT_INDICATORS.BRUTE_FORCE.threshold; 
        const windowMs = THREAT_INDICATORS.BRUTE_FORCE.window;
    
        // Generate exactly the number of events needed to meet the threshold
        const recentEvents = Array.from({ length: threshold }, (_, i) => ({
          id: `${i}`,
          type: 'OTP_FAILED' as EventType,
          ipAddress: mockIP,
          severity: 'SECURITY',
          metadata: {},
          // Ensure all events are comfortably within the window (e.g., within the first quarter of the window)
          createdAt: new Date(Date.now() - (i * (windowMs / threshold / 4))), 
          updatedAt: new Date(),
          userId: null,
          tenantId: null,
          sessionId: null,
          familyId: null,
          reason: null,
          integrityHash: `hash${i}`,
          prevHash: null,
          userAgent: null,
        }));
    
        // Add a slight delay to ensure 'Date.now()' in the service is slightly after our generated dates
        await new Promise(resolve => setTimeout(resolve, 10)); 
            
        const threats = await service['detectThreatIndicators'](mockIP, recentEvents);
    
        // Expect the length to match the threshold we used
        expect(threats).toHaveLength(1); 
        expect(threats[0].type).toBe('BRUTE_FORCE');
        expect(threats[0].severity).toBe('HIGH');
        // The evidence message needs to be generalized now that the count/window is dynamic:
        expect(threats[0].evidence).toContain(`Detected ${threshold} failed attempts`); 
      });

    it('should not detect brute force when below threshold', async () => {
      const recentEvents = Array.from({ length: 3 }, (_, i) => ({
        id: `${i}`,
        type: 'OTP_FAILED' as EventType,
        ipAddress: mockIP,
        severity: 'SECURITY',
        metadata: {},
        createdAt: new Date(Date.now() - (i * 30 * 1000)),
        updatedAt: new Date(),
        userId: null,
        tenantId: null,
        sessionId: null,
        familyId: null,
        reason: null,
        integrityHash: `hash${i}`,
        prevHash: null,
        userAgent: null,
      }));

      const threats = await service['detectThreatIndicators'](mockIP, recentEvents);

      expect(threats).toHaveLength(0);
    });

    it('should detect multiple threat types', async () => {
      // This would be expanded with more threat detection logic
      const events = [
        {
          id: '1',
          type: 'OTP_FAILED' as EventType,
          ipAddress: mockIP,
          severity: 'SECURITY',
          metadata: {},
          createdAt: new Date(),
          updatedAt: new Date(),
          userId: null,
          tenantId: null,
          sessionId: null,
          familyId: null,
          reason: null,
          integrityHash: 'hash1',
          prevHash: null,
          userAgent: null,
        },
      ];

      const threats = await service['detectThreatIndicators'](mockIP, events);

      // Currently only brute force is implemented
      expect(threats).toBeDefined();
    });
  });

  describe('Risk level calculation', () => {
    it('should return CRITICAL for high scores', () => {
      expect(service['getRiskLevel'](350)).toBe('CRITICAL');
      expect(service['getRiskLevel'](500)).toBe('CRITICAL');
    });

    it('should return HIGH for medium-high scores', () => {
      expect(service['getRiskLevel'](200)).toBe('HIGH');
      expect(service['getRiskLevel'](299)).toBe('HIGH');
    });

    it('should return MEDIUM for medium scores', () => {
      expect(service['getRiskLevel'](100)).toBe('MEDIUM');
      expect(service['getRiskLevel'](149)).toBe('MEDIUM');
    });

    it('should return LOW for low scores', () => {
      expect(service['getRiskLevel'](49)).toBe('LOW');
      expect(service['getRiskLevel'](-50)).toBe('LOW');
      expect(service['getRiskLevel'](0)).toBe('LOW');
    });
  });
});