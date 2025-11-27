// ip-reputation.blocking.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { IPReputationService } from '../ip-reputation.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { SecurityMonitoringService } from '@/security/security-monitor.service';
import { RedisService } from '@/redis/redis.service';
import { ConfigService } from '@nestjs/config';

describe('IPReputationService - Blocking & Whitelisting', () => {
  let service: IPReputationService;
  let prismaService: jest.Mocked<PrismaService>;
  let eventLogService: jest.Mocked<EventLogService>;

  const mockIP = '192.168.1.1';

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        IPReputationService,
        {
          provide: PrismaService,
          useValue: {
            iPBlock: {
              findFirst: jest.fn(),
              upsert: jest.fn(),
              deleteMany: jest.fn(),
            },
            iPWhitelist: {
              findFirst: jest.fn(),
              upsert: jest.fn(),
              deleteMany: jest.fn(),
            },
            $transaction: jest.fn(),
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
          useValue: {},
        },
        {
          provide: RedisService,
          useValue: {
            del: jest.fn(),
          },
        },
        {
          provide: ConfigService,
          useValue: {},
        },
      ],
    }).compile();

    service = module.get<IPReputationService>(IPReputationService);
    prismaService = module.get(PrismaService);
    eventLogService = module.get(EventLogService);
  });

  describe('IP Blocking', () => {
    it('should block IP successfully', async () => {
      prismaService.$transaction.mockImplementation(async (callback) => {
        return await callback(prismaService);
      });

      await service.blockIP(mockIP, 'Test block reason', 3600000);

      expect(prismaService.iPBlock.upsert).toHaveBeenCalledWith({
        where: { ip: mockIP },
        update: {
          reason: 'Test block reason',
          expiresAt: expect.any(Date),
          blockedAt: expect.any(Date),
        },
        create: {
          ip: mockIP,
          reason: 'Test block reason',
          expiresAt: expect.any(Date),
          blockedAt: expect.any(Date),
        },
      });
      expect(eventLogService.logEvent).toHaveBeenCalledWith('SECURITY_CSRF_ERROR', {
        ipAddress: mockIP,
        metadata: {
          reason: 'IP_BLOCKED',
          blockReason: 'Test block reason',
          score: undefined,
        },
        severity: 'CRITICAL',
      });
    });

    it('should unblock IP successfully', async () => {
      await service.unblockIP(mockIP);

      expect(prismaService.iPBlock.deleteMany).toHaveBeenCalledWith({
        where: { ip: mockIP, expiresAt: { gte: expect.any(Date) } },
      });
    });

    it('should check if IP is blocked', async () => {
      prismaService.iPBlock.findFirst.mockResolvedValue({
        id: '1',
        ip: mockIP,
        reason: 'Test',
        blockedAt: new Date(),
        expiresAt: new Date(Date.now() + 3600000),
        createdAt: new Date(),
      });

      const isBlocked = await service.isIPBlocked(mockIP);

      expect(isBlocked).toBe(true);
      expect(prismaService.iPBlock.findFirst).toHaveBeenCalledWith({
        where: {
          ip: mockIP,
          expiresAt: { gte: expect.any(Date) },
        },
      });
    });

    it('should get block info', async () => {
      const mockBlockInfo = {
        id: '1',
        ip: mockIP,
        reason: 'Test block',
        blockedAt: new Date(),
        expiresAt: new Date(Date.now() + 3600000),
        createdAt: new Date(),
      };
      prismaService.iPBlock.findFirst.mockResolvedValue(mockBlockInfo);

      const result = await service.getBlockInfo(mockIP);

      expect(result).toEqual(mockBlockInfo);
    });
  });

  describe('IP Whitelisting', () => {
    it('should whitelist IP successfully', async () => {
      jest.spyOn(service, 'isIPBlocked').mockResolvedValue(true);
      jest.spyOn(service, 'unblockIP').mockResolvedValue(undefined);

      await service.whitelistIP(mockIP, 'Test whitelist reason');

      expect(prismaService.iPWhitelist.upsert).toHaveBeenCalledWith({
        where: { ip: mockIP },
        update: { reason: 'Test whitelist reason' },
        create: { ip: mockIP, reason: 'Test whitelist reason' },
      });
      expect(service.unblockIP).toHaveBeenCalledWith(mockIP);
    });

    it('should remove IP from whitelist', async () => {
      await service.removeWhitelistIP(mockIP);

      expect(prismaService.iPWhitelist.deleteMany).toHaveBeenCalledWith({
        where: { ip: mockIP },
      });
    });

    it('should check if IP is whitelisted', async () => {
      prismaService.iPWhitelist.findFirst.mockResolvedValue({
        id: '1',
        ip: mockIP,
        reason: 'Test',
        addedAt: new Date(),
        addedBy: null,
      });

      const isWhitelisted = await service.isIPWhitelisted(mockIP);

      expect(isWhitelisted).toBe(true);
    });
  });
});