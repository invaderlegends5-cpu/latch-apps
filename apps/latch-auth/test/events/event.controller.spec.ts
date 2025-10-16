import { EventController } from '../../src/events/event.controller';
import { EventLogService } from '../../src/events/event.service';

// Mock Prisma $Enums.EventType safely, preserving PrismaClient
jest.mock('@prisma/client', () => {
  const originalModule = jest.requireActual('@prisma/client');
  return {
    ...originalModule,
    $Enums: {
      ...originalModule.$Enums,
      EventType: {
        LOGIN_SUCCESS: 'LOGIN_SUCCESS',
        LOGOUT: 'LOGOUT',
        REFRESH: 'REFRESH',
        TOKEN_REUSE: 'TOKEN_REUSE',
        LOGOUT_ATTEMPT_INVALID: 'LOGOUT_ATTEMPT_INVALID',
      },
    },
  };
});

describe('EventAdminController', () => {
  let ctrl: EventController;
  let mockEvents: Partial<EventLogService>;
  const mockReq = { user: { tenantId: 't1' } } as any;

  beforeEach(() => {
    mockEvents = { queryEvents: jest.fn().mockResolvedValue([{ id: 1 }]) };
    ctrl = new EventController(mockEvents as any);
  });

  it('calls queryEvents with provided filters', async () => {
    await ctrl.byType(
      mockRes,
      'LOGIN_SUCCESS',
      10, // limit
      0, // offset
    );

    expect(mockEvents.findByType).toHaveBeenCalledWith(
      'LOGIN_SUCCESS',
      10,
      0,
      undefined,
      undefined,
    );
  });

  it('returns ok + data', async () => {
    const res = await ctrl.getEvents(mockReq);
    expect(res).toEqual({ ok: true, count: 1, data: [{ id: 1 }] });
  });
});
