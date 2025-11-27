// ip-reputation.anomaly-detection.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { IPReputationService } from '../ip-reputation.service';
import { EventLogService } from '@/events/event.service';
import { PrismaService } from '@/prisma/prisma.service';
import { SecurityMonitoringService } from '@/security/security-monitor.service';
import { RedisService } from '@/redis/redis.service';
import { ConfigService } from '@nestjs/config';
import { EventType } from '@/events/event.types';

describe('IPReputationService - Anomaly Detection', () => {
  let service: IPReputationService;
  let eventLogService: jest.Mocked<EventLogService>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        IPReputationService,
        {
          provide: EventLogService,
          useValue: {
            event$: {
              subscribe: jest.fn(),
            },
          },
        },
        {
          provide: PrismaService,
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
    eventLogService = module.get(EventLogService);
  });

  describe('Anomaly detection', () => {
    it('should start anomaly detection on initialization', () => {
      service['startAnomalyDetection']();

      expect(eventLogService.event$.subscribe).toHaveBeenCalled();
    });

    it('should track request patterns', () => {
      const ip = '192.168.1.1';
      
      service['trackRequestPattern'](ip);
      service['trackRequestPattern'](ip);
      service['trackRequestPattern'](ip);

      const events = service['recentEvents'].get(ip);
      expect(events).toHaveLength(3);
      expect(events?.every(event => event instanceof Date)).toBe(true);
    });

    it('should cleanup old request patterns', () => {
      const ip = '192.168.1.1';
      const oldDate = new Date(Date.now() - 10 * 60 * 1000); // 10 minutes ago
      const recentDate = new Date(); // Now

      service['recentEvents'].set(ip, [oldDate, recentDate]);

      service['trackRequestPattern'](ip); // This triggers cleanup

      const events = service['recentEvents'].get(ip);
      expect(events).toHaveLength(2); // Old one removed, new one added
    });
  });
});