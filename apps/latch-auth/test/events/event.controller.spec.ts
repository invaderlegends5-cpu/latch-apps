import { EventController } from '../../src/events/event.controller';
import { EventLogService, PaginatedResult } from '../../src/events/event.service';
import { Response } from 'express';

type MockResponse = any;

// --- Mock Prisma enums safely ---
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

// --- Helper to mock Express Response ---
function createMockRes(): Response {
  return {
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
    send: jest.fn().mockReturnThis(),
    cookie: jest.fn().mockReturnThis(),
    clearCookie: jest.fn().mockReturnThis(),
  } as any;
}

describe('EventController', () => {
  let ctrl: EventController;
  let mockEvents: jest.Mocked<EventLogService>;
  let mockRes: MockResponse;

  beforeEach(() => {
    mockEvents = {
      findRecent: jest.fn(),
      findByType: jest.fn(),
      findByUser: jest.fn(),
      logEvent: jest.fn(),
    } as any;

    ctrl = new EventController(mockEvents);
    mockRes = createMockRes();
  });

  it('calls findByType with provided filters', async () => {
    const fake: PaginatedResult<any> = {
      data: [{ id: 1 }],
      meta: { total: 1, limit: 10, offset: 0, hasNext: false },
    };
    mockEvents.findByType.mockResolvedValue(fake);

    const result = await ctrl.byType(mockRes, 'LOGIN_SUCCESS', 10, 0);

    expect(mockEvents.findByType).toHaveBeenCalledWith(
      'LOGIN_SUCCESS',
      10,
      0,
      undefined,
      undefined,
    );
    expect(result).toEqual(fake);
  });

  it('calls findRecent and returns recent events', async () => {
    const fake: PaginatedResult<any> = {
      data: [{ id: 2, type: 'LOGOUT' }],
      meta: { total: 1, limit: 5, offset: 0, hasNext: false },
    };
    mockEvents.findRecent.mockResolvedValue(fake);

    const result = await ctrl.recent(mockRes, 5, 0);

    expect(mockEvents.findRecent).toHaveBeenCalledWith(5, 0, undefined, undefined);
    expect(result).toEqual(fake);
  });

  it('calls findByUser and returns user events', async () => {
    const fake: PaginatedResult<any> = {
      data: [{ id: 3, userId: 'u1' }],
      meta: { total: 1, limit: 5, offset: 0, hasNext: false },
    };
    mockEvents.findByUser.mockResolvedValue(fake);

    const result = await ctrl.byUser(mockRes, 'u1', 5, 0);

    expect(mockEvents.findByUser).toHaveBeenCalledWith(
      'u1',
      5,
      0,
      undefined,
      undefined,
    );
    expect(result).toEqual(fake);
  });
});
