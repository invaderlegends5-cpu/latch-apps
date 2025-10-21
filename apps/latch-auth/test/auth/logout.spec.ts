import { AuthController } from '../../src/auth/auth.controller';
import { AuthService } from '../../src/auth/auth.service';
import { EventLogService } from '../../src/events/event.service';
import { Response, Request } from 'express'; // 👈 IMPORT Response and Request
import { createMockRes } from 'test/utils/mock-response';

describe('AuthController.logout (two-event)', () => {
  let ctrl: AuthController;
  let mockAuth: Partial<AuthService>;
  let mockEvents: Partial<EventLogService>;
  let res: Response; // 👈 Properly typed
  let req: Request; // 👈 Properly typed

  beforeEach(() => {
    mockAuth = {
      getUserBySessionId: jest.fn(),
      getActiveSessionCount: jest.fn(),
      revokeSession: jest.fn(),
    };
    mockEvents = {
      logEvent: jest.fn(),
    };
  
    ctrl = new AuthController(mockAuth as any, mockEvents as any);
  
    res = {
      cookie: jest.fn().mockReturnThis(),       // 👈 ADD THIS
      clearCookie: jest.fn().mockReturnThis(),
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    } as unknown as Response;
    
  
    req = {
      ip: '1.2.3.4',
      headers: { 'user-agent': 'jest' },
      cookies: {},
    } as unknown as Request;
  });
  

  it('valid session → revokes, clears cookies, logs LOGOUT', async () => {
    const sessionId = 'sess-1';
    req.cookies = { latch_session: sessionId, latch_refresh: 'r' };
    (mockAuth.getUserBySessionId as jest.Mock).mockResolvedValue({
      id: 'user1',
      tenantId: 't1',
    });
    (mockAuth.getActiveSessionCount as jest.Mock).mockResolvedValue(3);
    (mockAuth.revokeSession as jest.Mock).mockResolvedValue(true);

    const result = await ctrl.logout(req as any, res as any);

    expect(mockAuth.getUserBySessionId).toHaveBeenCalledWith(
      sessionId,
      expect.any(Object),
    );
    expect(mockAuth.revokeSession).toHaveBeenCalledWith(
      sessionId,
      expect.any(Object),
    );
    expect(res.cookie).toHaveBeenCalled(); // ✅ Now works
    expect(mockEvents.logEvent).toHaveBeenCalledWith(
      'LOGOUT',
      expect.objectContaining({ userId: 'user1', tenantId: 't1' }),
    );
    expect(result).toEqual({ ok: true });
  });

  it('invalid/stale session → logs LOGOUT_ATTEMPT_INVALID then LOGOUT', async () => {
    const sessionId = 'sess-2';
    req.cookies = { latch_session: sessionId, latch_refresh: 'r' };
    (mockAuth.getUserBySessionId as jest.Mock).mockResolvedValue(null);

    const result = await ctrl.logout(req as any, res as any);

    expect(mockEvents.logEvent).toHaveBeenCalledWith(
      'LOGOUT_ATTEMPT_INVALID',
      expect.objectContaining({
        metadata: expect.objectContaining({ sessionId }),
      }),
    );
    expect(mockEvents.logEvent).toHaveBeenCalledWith(
      'LOGOUT',
      expect.objectContaining({ userId: null }),
    );
    expect(res.cookie).toHaveBeenCalled(); // ✅ Now works
    expect(result).toEqual({ ok: true });
  });
});