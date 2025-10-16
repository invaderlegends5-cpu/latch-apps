import { EventController } from '../../events/event.controller';
import { EventLogService } from '../../events/event.service';
import { BadRequestException } from '@nestjs/common';
import { Response } from 'express';

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

describe('EventController', () => {
  let ctrl: EventController;
  let mockEventLog: Partial<EventLogService>;
  let mockRes: Partial<Response>;

  beforeEach(() => {
    mockEventLog = {
      findRecent: jest.fn().mockResolvedValue({ data: [], meta: {} }),
      findByType: jest.fn().mockResolvedValue({ data: [], meta: {} }),
      findByUser: jest.fn().mockResolvedValue({ data: [], meta: {} }),
    };
    ctrl = new EventController(mockEventLog as any);
    mockRes = {} as Partial<Response>;
  });

  // ---------------------------
  // recent()
  // ---------------------------
  it('calls findRecent with correct args', async () => {
    await ctrl.recent(mockRes as any, 20, 10, '2024-01-01', '2024-02-01');
    expect(mockEventLog.findRecent).toHaveBeenCalledWith(
      20,
      10,
      new Date('2024-01-01').toISOString(),
      new Date('2024-02-01').toISOString(),
    );
  });

  it('throws BadRequestException if limit is invalid', async () => {
    await expect(ctrl.recent(mockRes as any, -5, 0)).rejects.toBeInstanceOf(
      BadRequestException,
    );
  });

  it('throws BadRequestException if from date is invalid', async () => {
    await expect(
      ctrl.recent(mockRes as any, 10, 0, 'invalid-date'),
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  // ---------------------------
  // byType()
  // ---------------------------
  it('calls findByType with correct args', async () => {
    await ctrl.byType(mockRes as any, 'LOGIN_SUCCESS', 15, 5);
    expect(mockEventLog.findByType).toHaveBeenCalledWith(
      'LOGIN_SUCCESS',
      15,
      5,
      undefined,
      undefined,
    );
  });

  it('throws BadRequestException when type missing', async () => {
    await expect(ctrl.byType(mockRes as any, '' as any)).rejects.toBeInstanceOf(
      BadRequestException,
    );
  });

  it('throws BadRequestException for invalid type value', async () => {
    // Mock Prisma enum validation failure
    jest
      .spyOn(Object, 'values')
      .mockReturnValueOnce(['LOGIN_SUCCESS', 'LOGOUT', 'REFRESH'] as any);
    await expect(
      ctrl.byType(mockRes as any, 'INVALID_TYPE'),
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  // ---------------------------
  // byUser()
  // ---------------------------
  it('calls findByUser with correct args', async () => {
    await ctrl.byUser(mockRes as any, 'user123', 25, 0);
    expect(mockEventLog.findByUser).toHaveBeenCalledWith(
      'user123',
      25,
      0,
      undefined,
      undefined,
    );
  });

  it('throws BadRequestException if userId missing', async () => {
    await expect(ctrl.byUser(mockRes as any, '' as any)).rejects.toBeInstanceOf(
      BadRequestException,
    );
  });

  it('throws BadRequestException if offset is invalid', async () => {
    await expect(
      ctrl.byUser(mockRes as any, 'user1', 10, -2),
    ).rejects.toBeInstanceOf(BadRequestException);
  });
});
