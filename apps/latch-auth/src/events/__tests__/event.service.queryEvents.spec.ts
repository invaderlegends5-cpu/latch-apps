import { EventLogService } from '../../events/event.service';
import { PrismaService } from '../../prisma/prisma.service';
import { ConfigService } from '@nestjs/config';

describe('EventLogService.queryEvents', () => {
  let service: EventLogService;
  let mockPrisma: any;
  let mockConfig: Partial<ConfigService>;

  beforeEach(() => {
    mockPrisma = {
      event: {
        findMany: jest.fn().mockResolvedValue([{ id: '1', type: 'LOGIN_SUCCESS' }]),
        count: jest.fn().mockResolvedValue(1),
      },
      user: { findMany: jest.fn().mockResolvedValue([]) },
      tenant: { findMany: jest.fn().mockResolvedValue([]) },
    };
    mockConfig = { get: jest.fn().mockReturnValue('dummy-secret') };

    service = new EventLogService(mockPrisma as any, mockConfig as any);
  });

  it('calls Prisma with correct filters (all parameters)', async () => {
    const startDate = new Date('2024-01-01');
    const endDate = new Date('2024-01-31');

    await service.queryEvents({
      tenantId: 't1',
      type: 'LOGIN_SUCCESS',
      userId: 'u1',
      sessionId: 's1',
      startDate,
      endDate,
      limit: 10,
      offset: 5,
    });

    expect(mockPrisma.event.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          tenantId: 't1',
          type: 'LOGIN_SUCCESS',
          userId: 'u1',
          sessionId: 's1',
          createdAt: { gte: startDate, lte: endDate },
        }),
        take: 10,
        skip: 5,
      }),
    );

    expect(mockPrisma.event.count).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          tenantId: 't1',
          type: 'LOGIN_SUCCESS',
          userId: 'u1',
        }),
      }),
    );
  });

  it('handles missing filters gracefully', async () => {
    await service.queryEvents({});
    expect(mockPrisma.event.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {},
        take: 50,
        skip: 0,
      }),
    );
  });

  it('applies only startDate', async () => {
    const startDate = new Date('2024-01-01');
    await service.queryEvents({ startDate });
    expect(mockPrisma.event.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { createdAt: { gte: startDate } },
      }),
    );
  });

  it('applies only endDate', async () => {
    const endDate = new Date('2024-01-31');
    await service.queryEvents({ endDate });
    expect(mockPrisma.event.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { createdAt: { lte: endDate } },
      }),
    );
  });

  it('returns paginated structure', async () => {
    const result = await service.queryEvents({ limit: 1, offset: 0 });
    expect(result).toEqual(
      expect.objectContaining({
        data: expect.any(Array),
        meta: expect.objectContaining({
          total: expect.any(Number),
          limit: 1,
          offset: 0,
          hasNext: expect.any(Boolean),
        }),
      }),
    );
  });
});
