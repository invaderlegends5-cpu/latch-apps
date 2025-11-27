// ip-reputation.cleanup.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { IPReputationService } from '../ip-reputation.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { SecurityMonitoringService } from '@/security/security-monitor.service';
import { RedisService } from '@/redis/redis.service';
import { ConfigService } from '@nestjs/config';

describe('IPReputationService - Cleanup', () => {
  let service: IPReputationService;
  let prismaService: jest.Mocked<PrismaService>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        IPReputationService,
        {
          provide: PrismaService,
          useValue: {
            iPBlock: {
              deleteMany: jest.fn(),
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
    prismaService = module.get(PrismaService);
  });

  describe('Cleanup tasks', () => {
    it('should cleanup expired blocks and old request patterns', async () => {
      // Set up some old request patterns
      const oldIP = '192.168.1.100';
      const recentIP = '192.168.1.200';
      const oldDate = new Date(Date.now() - 10 * 60 * 1000); // 10 minutes ago (older than 5m window)
      const recentDate = new Date(); // Now

      service['recentEvents'].set(oldIP, [oldDate]);
      service['recentEvents'].set(recentIP, [recentDate]);

      await service['cleanup']();

      expect(prismaService.iPBlock.deleteMany).toHaveBeenCalledWith({
        where: { expiresAt: { lt: expect.any(Date) } },
      });

      // Old IP should be removed, recent IP should remain
      expect(service['recentEvents'].has(oldIP)).toBe(false);
      expect(service['recentEvents'].has(recentIP)).toBe(true);
    });

    it('should handle cleanup errors gracefully', async () => {
      prismaService.iPBlock.deleteMany.mockRejectedValue(new Error('DB error'));

      await expect(service['cleanup']()).resolves.not.toThrow();
    });
  });
});